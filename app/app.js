/**
 * tools-extract-service
 *
 * node.js web service for puppeteer/chrome to generate extract data from HTML.
 *
 * Accepts POST requests to /extract with a `url` parameter.
 *
 * This service is not meant to be exposed to the public, and use of this
 * service should be mediated by another application with access controls.
 */
const async = require('async');
const bodyParser = require('body-parser');
const express = require('express');
const fs = require('fs');
const http = require('http');
const log = require('./log');
const methodOverride = require('method-override');
const os = require('os');
const path = require('path');
const puppeteer = require('puppeteer-extra');
const puppeteerPrefs = require('puppeteer-extra-plugin-user-preferences');
const puppeteerStealth = require('puppeteer-extra-plugin-stealth');
const { query, validationResult } = require('express-validator');
const { Semaphore } = require('await-semaphore');
const timers = require('node:timers/promises');
const url = require('url');
const util = require('util');

const dump = util.inspect;

// It's impossible to regex a CSS selector so we'll assemble a list of the most
// common characters. Feel free to add to this list if it's preventing a legit
// selector from being used.
//
// The space at the beginning of this string is intentional.
const allowedSelectorChars = ' #.[]()-_=+:~^*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

const sleep = ms => new Promise(res => setTimeout(res, ms));

// Helper function.
function ated(request) {
  return request.headers['x-forwarded-for']
    || request.connection.remoteAddress
    || request.socket.remoteAddress
    || (request.connection.socket ? request.connection.socket.remoteAddress : null);
}

const isEmptyDir = async function(path, timeout = 10000, delay = 100) {
  const tid = setTimeout(() => {
    const msg = `Timeout of ${timeout} ms exceeded waiting for ${path}`;
    throw Error(msg);
  }, timeout);

  for (;;) {
    try {
      files = fs.readdirSync(path);
      if (files.length > 0) {
        if (files[0].indexOf('crdownload') === -1) {
          clearTimeout(tid);
          return false;
        }
      }
    }
    catch (err) {}

    await timers.setTimeout(delay);
  }
}

function isFile(fileName) {
  return fs.lstatSync(fileName).isFile();
};

function getFile(dir) {
  let files = fs.readdirSync(dir)
    .map(fileName => {
      return path.join(dir, fileName);
    })
    .filter(isFile);

  if (files.length === 0) {
    throw new Error(`No files found in ${dir}`);
  }
  if (files.length > 1) {
    throw new Error(`Multiple files found in ${dir}. Expected only one.`);
  }
  return files[0];
}

/**
 * A semaphore to limit the maximum number of concurrent active requests to
 * puppeteer, and require that new requests wait until previous ones are
 * disconnected before connecting.
 */
const PUPPETEER_SEMAPHORE = new Semaphore(process.env.MAX_CONCURRENT_REQUESTS || 4);

/**
 * Launch Puppeteer.
 *
 * Using the launch() command multiple times results in multiple Chromium procs
 * but (just like a normal web browser) we only want one. We'll open a new "tab"
 * each time our `/extract` route is invoked by reusing the connection.
 *
 * Allow the use of the standard puppeteer browser executable override.
 */
let browserWSEndpoint = '';

async function connectPuppeteer() {
  let browser;
  puppeteer.use(puppeteerStealth());
  puppeteer.use(puppeteerPrefs({
    userPrefs: {
      download: {
        prompt_for_download: false,
        directory_upgrade: true,
        extensions_to_open: 'applications/pdf',
      },
      plugins: {
        always_open_pdf_externally: true,
        plugins_disabled: ['Chrome PDF Viewer'],
      },
  }}));

  if (browserWSEndpoint) {
    browser = await puppeteer.connect({ browserWSEndpoint });
  } else {
    // Initialize Puppeteer
    browser = await puppeteer.launch({
      userDataDir: '/tmp/FakeChromeProfile',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome',
      args: [
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--remote-debugging-port=9222',
        '--remote-debugging-address=0.0.0.0',
        '--no-sandbox',
      ],
      headless: true,
      dumpio: false, // set to `true` for debugging
    });

    // Log UA for visibility in ELK.
    const ua = await browser.userAgent();
    log.info(`New connection to Chrome. UA: ${ua}`);

    // Create re-usable connection.
    browserWSEndpoint = browser.wsEndpoint();
  }

  return browser;
}

// Set up the Express app
const app = express();
const apiTimeout = 60 * 1000;

app.set('env', process.env.NODE_ENV || 'dockerdev');
app.set('port', process.env.PORT || 80);

app.use(bodyParser.urlencoded({
  extended: true,
  limit: '10mb',
  uploadDir: '/tmp',
}));

app.use(methodOverride());

app.disable('x-powered-by');

app.use((err, req, res, next) => {
  if (process.env.NODE_ENV !== 'test') {
    log.error(`Error: ${JSON.stringify(err)}`);
  }

  req.setTimeout(apiTimeout, () => {
      let err = new Error('Request Timeout');
      err.status = 408;
      next(err);
  });

  res.status(err.code || 500);
  res.send('Error');
});

// Health check
app.get('/status', (req, res) => {
  // Calculate the number of in-flight requests. The semaphore count is
  // decreased by 1 for each concurrent extract, so the maths are simple.
  const semaphoreSize = process.env.MAX_CONCURRENT_REQUESTS || 4;
  const inFlightRequests = semaphoreSize - PUPPETEER_SEMAPHORE.count;

  if (inFlightRequests <= semaphoreSize) {
    res.status(200).send(`Healthy. There are ${inFlightRequests}/${process.env.MAX_CONCURRENT_REQUESTS} requests in flight.`);
  } else {
    res.status(429).send(`Unhealthy. There are ${inFlightRequests}/${process.env.MAX_CONCURRENT_REQUESTS} requests in flight.`);
  }
});

// Extract
app.post('/extract', [
  query('url', 'Must be a valid URL with protocol and no auth').notEmpty().isURL({ require_protocol: true, disallow_auth: true, validate_length: false }),
  query('selector', `Must be a CSS selector made of the following characters: ${allowedSelectorChars}`).optional().isWhitelisted(allowedSelectorChars),
  query('element', 'Element to click').notEmpty(),
  query('element2', 'Deprecated, element may be an array').optional(),
  query('attribute', 'Attribute to extract').notEmpty(),
  query('file', 'Include the file as blob').optional().isInt(),
  query('width', 'Must be an integer with no units').optional().isInt(),
  query('height', 'Must be an integer with no units').optional().isInt(),
  query('user', 'Must be an alphanumeric string').optional().isAlphanumeric(),
  query('pass', 'Must be an alphanumeric string').optional().isAlphanumeric(),
  query('service', 'Must be an alphanumeric string identifier (hyphens, underscores are also allowed).').matches(/^[A-Za-z0-9_-]+$/),
  query('header', 'Custom header').optional(),
  query('delay', 'Must be an integer between 0-10000 inclusive.').optional().isInt({ min: 0, max: 10000 }),
  query('debug', 'Must be one of the following (case insensitive): true, false').optional().toLowerCase().isBoolean(),
], (req, res) => {
  // debug
  log.debug('Request received', { query: url.parse(req.url).query });

  // Ensure a passed url is on the permitted list or includes a substring that
  // is on the permitted list.
  if (req.query.url) {
    let urlHash;

    try {
      urlHash = new URL(req.query.url);
    } catch (err) {
      return res.status(400).json({
        errors: [
          {
            location: 'query',
            param: 'url',
            value: req.query.url,
            msg: `${req.query.url} is not a valid URL. Make sure the protocol is present. Example: https://example.com/path`,
          },
        ],
      });
    }
  }

  // Validate input errors, return 400 for any problems.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Housekeeping
  const startTime = Date.now();

  // Assign validated querystring params to variables and set defaults.
  const fnUrl = req.query.url || false;
  const fnSelector = req.query.selector || '';
  const fnAttribute = req.query.attribute || '';
  const fnFile = req.query.file || false;

  // Element might be an array.
  let el = [];
  if (Array.isArray(req.query.element)) {
    el = req.query.element;
  }
  // If it's not an array, make it one.
  if (typeof el === 'string') {
    el = [el];
  }

  const fnElement = el;

  const fnWidth = Number(req.query.width) || 800;
  const fnHeight = Number(req.query.height) || 600;
  const fnAuthUser = req.query.user || '';
  const fnAuthPass = req.query.pass || '';
  const fnCookies = req.query.cookies || '';
  const fnService = req.query.service || '';
  const fnCustomHeader = req.query.header || '';
  const fnDelay = Number(req.query.delay) || 0;
  const fnDebug = Boolean(req.query.debug === 'true') || false;
  const fnBlock = req.query.block || '';

  let pdfLink = '';
  let pdfBlob = '';
  let screenshot = '';
  let downloadPath = '';

  // Make a nice blob for the logs. ELK will sort this out. Blame Emma.
  const ip = ated(req);
  const lgParams = {
    url: fnUrl,
    selector: fnSelector,
    element: fnElement,
    attribute: fnAttribute,
    file: fnFile,
    authuser: fnAuthUser,
    authpass: (fnAuthPass ? '*****' : ''),
    cookies: fnCookies,
    service: fnService,
    custom_header: fnCustomHeader,
    ip,
    delay: fnDelay,
    debug: '', // gets filled in as needed
    block: fnBlock,
  };

  async.series(
    [
      function generateResponse(cb) {
        /**
         * Puppeteer code to extract data.
         */
        async function extract() {
          await PUPPETEER_SEMAPHORE.use(async () => {
            // Access the Chromium instance by either launching or connecting
            // to Puppeteer.
            const browser = await connectPuppeteer().catch((err) => {
              throw err;
            });

            // Create a new browser context. As of Puppeteer 22.0.0 all new
            // browser contexts are isolated (cookies/localStorage/etc).
            // So they renamed the previous function name to remove the word
            // Incognito. It still offers the same isolation as before.
            //
            // @see https://github.com/puppeteer/puppeteer/releases/tag/puppeteer-core-v22.0.0
            // @see https://github.com/puppeteer/puppeteer/pull/11834/files
            const context = await browser.createBrowserContext();

            // Create a new tab/page within the context.
            const page = await context.newPage();

            try {
              // Set the user agent.
              const userAgent = process.env.USER_AGENT || 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';
              await page.setUserAgent(userAgent);

              // Set custom headers if provided.
              if (fnCustomHeader) {
                const customHeaders = {};
                fnCustomHeader.split(';').forEach((header) => {
                  const [key, value] = header.split('=');
                  customHeaders[key.trim()] = value.trim();
                });
                await page.setExtraHTTPHeaders(customHeaders);
              }

              // Set duration until Timeout
              await page.setDefaultNavigationTimeout(30 * 1000);

              // We want to intercept requests to dump logs or block domains.
              if (fnDebug || fnBlock) {
                await page.setRequestInterception(true);
              }

              if (fnDebug) {
                // Log caught exceptions
                page.on('error', (err) => {
                  lgParams.debug += err.toString();
                });

                // Log uncaught exceptions
                page.on('pageerror', (err) => {
                  lgParams.debug += err.toString();
                });

                // Forward all console output
                page.on('console', (msg) => {
                  const errText = msg._args
                    && msg._args[0]
                    && msg._args[0]._remoteObject
                    && msg._args[0]._remoteObject.value;
                  lgParams.debug += `${msg._type.padStart(7)} ${dump(errText)}\n`;
                });
              }

              // Use HTTP auth if needed (for testing staging envs)
              if (fnAuthUser && fnAuthPass) {
                await page.authenticate({ username: fnAuthUser, password: fnAuthPass });
              }

              // Set viewport dimensions
              await page.setViewport({
                width: Math.round(fnWidth + Math.random() * 100, 0),
                height: Math.round(fnHeight + Math.random() * 100)
              });

              // Download needed.
              if (fnFile) {
                downloadPath = path.join(os.tmpdir(), startTime.toString());
                // Create a unique download path.
                fs.mkdirSync(downloadPath, { recursive: true });
                const client = await page.target().createCDPSession();
                await client.send('Page.setDownloadBehavior', {
                  behavior: 'allow',
                  downloadPath: downloadPath
                });
                log.info(lgParams, `Download directory created: ${downloadPath}`);
              }

              // Compile cookies if present. We must manually specify some extra
              // info such as host/path in order to create a valid cookie.
              const cookies = [];
              if (fnCookies) {
                fnCookies.split('; ').map((cookie) => {
                  const thisCookie = {};
                  const [name, value] = cookie.split('=');

                  thisCookie.url = fnUrl;
                  thisCookie.name = name;
                  thisCookie.value = value;

                  cookies.push(thisCookie);
                });
              }

              // Set cookies.
              cookies.forEach(async (cookie) => {
                await page.setCookie(cookie).catch((err) => {
                  log.error(err);
                });
              });

              await page.goto(fnUrl, {
                waitUntil: ['load'],
              });

              // Wait and reload.
              await sleep(1000);
              await page.goto(fnUrl, {
                waitUntil: ['load'],
              });

              if (fnSelector) {
                // Make sure our selector is in the DOM.
                await page.waitForSelector(fnSelector);
              }

              if (fnDelay > 0) {
                await sleep(fnDelay);
              }

              // Loop through the elements to click.
              for (const element of fnElement) {
                log.info(lgParams, `Processing element: ${element}`);
                let el = element.trim();
                // If element contains a pipe, split it.
                let el2 = '';
                if (element.indexOf('|') !== -1) {
                  const parts = element.split('|');
                  el = parts[1].trim();
                  el2 = parts[0].trim();
                }

                let pdfElement = await page.$(el);
                if (pdfElement) {
                  pdfLink = await page.evaluate((el, fnAttribute) => {
                    return el.getAttribute(fnAttribute);
                  }, pdfElement, fnAttribute);
                }

                // If the element is not found, try next one.
                if (!pdfElement || !pdfLink) {
                  log.warn(lgParams, `Element ${el} not found or does not have attribute ${fnAttribute}.`);
                  continue;
                }

                // Grab the file as a blob if requested.
                if (fnFile) {
                  // Try the second one if specified.
                  if (el2) {
                    pdfElement = await page.$(el2);
                    if (pdfElement) {
                      pdfLink = await page.evaluate((el, fnAttribute) => {
                        return el.getAttribute(fnAttribute);
                      }, pdfElement, fnAttribute);
                    }
                  }

                  let fileName = path.basename(pdfLink);
                  if (!fileName) {
                    fileName = `downloaded-${Date.now()}.pdf`;
                  }
                  let filePath = path.resolve(downloadPath, fileName);
                  log.info(lgParams, `File will be saved as: ${filePath}`);

                  try {
                      // Use puppeteer to download file.
                      await sleep(444);
                      log.info(lgParams, `Will click on first element: ${el}`);
                      await page.evaluate((el) => {
                        const link = document.querySelector(el);
                        if (link) {
                          link.target = '';
                          link.click();
                          return link.href;
                        }
                      }, el);
                      await sleep(555);

                      // Make a screenshot of the page if requested.
                      screenshot = await page.screenshot({
                        encoding: 'base64',
                        fullPage: true,
                      });
                      log.info(lgParams, `Screenshot taken, size: ${screenshot.length} bytes`);

                      // Use second element if provided.
                      if (el2) {
                        log.info(lgParams, `Will click on second element: ${el2}`);
                        await page.waitForSelector(el2);
                        await page.evaluate((el) => {
                          const link = document.querySelector(el);
                          if (link) {
                            link.target = '';
                            link.click();
                            return link.href;
                          }
                        }, el2);
                        await sleep(666);
                      }

                      // Wait for file to be downloaded.
                      await isEmptyDir(downloadPath);

                      await new Promise((resolve, reject) => {
                        filePath = getFile(downloadPath);
                        log.info(lgParams, `File downloaded to: ${filePath}`);
                        pdfBlob = fs.readFileSync(filePath);
                        pdfBlob = Buffer.from(pdfBlob).toString('base64');
                        log.info(lgParams, `Blob size: ${pdfBlob.length}`);

                        // Remove the file.
                        fs.unlink(filePath, (err) => {
                          if (err) {
                            log.error(lgParams, err);
                          } else {
                            log.info(lgParams, `Deleted: ${filePath}`);
                            fs.rmdirSync(downloadPath);
                          }
                        });

                        resolve();
                      });

                      // Exit the loop after downloading the first valid link.
                      break;
                  } catch (error) {
                    log.error(lgParams, `Failed to download from link: ${pdfLink}`, error);
                    // Try to remove the download directory. If it is not empty, this will fail, so log that.
                    try {
                      fs.rmdirSync(downloadPath);
                    } catch (error) {
                      log.error(lgParams, `Unable to remove download directory: ${downloadPath}`, error);
                    }
                  }
                }
              }
            } catch (err) {
              log.error(lgParams, err);
              throw err;
            } finally {
              // Disconnect from Puppeteer process.
              //await context.close();
              await browser.disconnect();
            }
          });
        }

        /**
         * Express response and tmp file cleanup.
         */
        extract().then(() => {
          res.charset = 'utf-8';

          res.contentType('application/json');
          res.status(200).json({
            url: fnUrl,
            selector: fnSelector,
            element: fnElement,
            attribute: fnAttribute,
            pdf: pdfLink,
            blob: pdfBlob,
            screenshot: screenshot,
          });

          const duration = ((Date.now() - startTime) / 1000);
          res.end();
          lgParams.duration = duration;
          log.info(lgParams, `All extracted in ${duration} seconds.`);
        }).catch((err) => cb(err));
      },
    ],
    (err) => {
      const duration = ((Date.now() - startTime) / 1000);

      if (err) {
        lgParams.fail = true;
        lgParams.stack_trace = err.stack;
        lgParams.duration = duration;
        log.error(lgParams, `Extract FAILED in ${duration} seconds. ${err}`);

        //
        // Detect known issues and send more appropriate error codes.
        //

        // URL can't be reached.
        if (err.message.indexOf('ERR_NAME_NOT_RESOLVED') !== -1) {
          return res.status(400).json({
            errors: [
              {
                location: 'query',
                param: 'url',
                value: req.query.url,
                msg: 'The URL could not be loaded. Confirm that it exists.',
              },
            ],
          });
        }

        // URL timed out, throw shade.
        if (err.message.indexOf('ERR_TIMED_OUT') !== -1 || err.name === 'TimeoutError') {
          return res.status(502).json({
            errors: [
              {
                msg: 'Extract is working, but the target URL timed out.',
              },
            ],
          });
        }

        //
        // Default
        //
        // If we didn't detect a specific error above, send a generic 500.
        //
        res.status(500).json({
          errors: [
            {
              msg: 'Internal Server Error',
            },
          ],
        });
      }
    },
  );
});

http.createServer(app).listen(app.get('port'), () => {
  log.info('⚡️ Express server configured for', (process.env.MAX_CONCURRENT_REQUESTS || 4), 'concurrent requests listening on port:', app.get('port'));
});
