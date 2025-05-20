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
const path = require('path');
const puppeteer = require('puppeteer');
const { query, validationResult } = require('express-validator');
const { Semaphore } = require('await-semaphore');
const url = require('url');
const util = require('util');

const dump = util.inspect;

// It's impossible to regex a CSS selector so we'll assemble a list of the most
// common characters. Feel free to add to this list if it's preventing a legit
// selector from being used.
//
// The space at the beginning of this string is intentional.
const allowedSelectorChars = ' #.[]()-_=+:~^*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';


// Helper function.
function ated(request) {
  return request.headers['x-forwarded-for']
    || request.connection.remoteAddress
    || request.socket.remoteAddress
    || (request.connection.socket ? request.connection.socket.remoteAddress : null);
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

  if (browserWSEndpoint) {
    browser = await puppeteer.connect({ browserWSEndpoint });
  } else {
    // Initialize Puppeteer
    browser = await puppeteer.launch({
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome',
      args: [
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--remote-debugging-port=9222',
        '--remote-debugging-address=0.0.0.0',
        '--no-sandbox',
      ],
      headless: 'new',
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
  query('element', 'Element to extract').notEmpty(),
  query('attribute', 'Attribute to extract').notEmpty(),
  query('file', 'Include the file as blob').optional().isInt(),
  query('width', 'Must be an integer with no units').optional().isInt(),
  query('height', 'Must be an integer with no units').optional().isInt(),
  query('user', 'Must be an alphanumeric string').optional().isAlphanumeric(),
  query('pass', 'Must be an alphanumeric string').optional().isAlphanumeric(),
  query('service', 'Must be an alphanumeric string identifier (hyphens, underscores are also allowed).').matches(/^[A-Za-z0-9_-]+$/),
  query('ua', '').optional(),
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
  const fnElement = req.query.element || '';
  const fnAttribute = req.query.attribute || '';
  const fnFile = req.query.file || false;

  const fnWidth = Number(req.query.width) || 800;
  const fnHeight = Number(req.query.height) || 600;
  const fnAuthUser = req.query.user || '';
  const fnAuthPass = req.query.pass || '';
  const fnCookies = req.query.cookies || '';
  const fnService = req.query.service || '';
  const fnUserAgent = req.query.ua || req.headers['user-agent'] || '';
  const fnDelay = Number(req.query.delay) || 0;
  const fnDebug = Boolean(req.query.debug === 'true') || false;
  const fnBlock = req.query.block || '';

  let pdfLink = '';
  let pdfBlob = '';
  let downloadPath = '';

  // Make a nice blob for the logs. ELK will sort this out. Blame Emma.
  const ip = ated(req);
  const lgParams = {
    url: fnUrl,
    selector: fnSelector,
    element: fnElement,
    attribute: fnAttribute,
    authuser: fnAuthUser,
    authpass: (fnAuthPass ? '*****' : ''),
    cookies: fnCookies,
    service: fnService,
    ua: fnUserAgent,
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
              // Set duration until Timeout
              await page.setDefaultNavigationTimeout(60 * 1000);

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
              await page.setViewport({ width: fnWidth, height: fnHeight });

              // Download needed.
              if (fnFile) {
                const client = await page.target().createCDPSession();
                await client.send('Page.setDownloadBehavior', {
                  behavior: 'allow',
                  downloadPath: downloadPath
                });
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
                waitUntil: ['load', 'networkidle0'],
              });

              if (fnSelector) {
                // Make sure our selector is in the DOM.
                await page.waitForSelector(fnSelector);
              }

              let pdfElement = await page.$(fnElement);
              if (pdfElement) {
                pdfLink = await page.evaluate((el, fnAttribute) => {
                  return el.getAttribute(fnAttribute);
                }, pdfElement, fnAttribute);
              }
              log.info(lgParams, `Extracted ${fnElement} from ${fnUrl} with attribute ${fnAttribute} and value ${pdfLink}`);

              // Grab the file as a blob if requested.
              if (fnFile) {
                const fileName = path.basename(pdfLink);
                const filePath = path.resolve(downloadPath, fileName);

                if (!pdfLink.startsWith('http')) {
                  // Use hostname from the URL.
                  const urlObj = new URL(fnUrl);
                  const hostname = urlObj.hostname;
                  const port = urlObj.port ? `:${urlObj.port}` : '';
                  const protocol = urlObj.protocol;
                  const baseUrl = `${protocol}//${hostname}${port}`;
                  pdfLink = `${baseUrl}${pdfLink}`;
                }

                try {
                    // Download the file
                    const response = await page.goto(pdfLink);
                    fs.writeFileSync(filePath, await response.buffer());
                    console.log(`Downloaded: ${fileName}`);

                    // Read the file
                    pdfBlob = fs.readFileSync(filePath);
                    pdfBlob = Buffer.from(pdfBlob).toString('base64');
                } catch (error) {
                    console.error(`Failed to download from link: ${pdfLink}`, error);
                }

              }
            } catch (err) {
              log.error(err);
              throw err;
            } finally {
              // Disconnect from Puppeteer process.
              await context.close();
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
          });

          const duration = ((Date.now() - startTime) / 1000);
          res.end();
          lgParams.duration = duration;
          log.info(lgParams, `PNG successfully generated in ${duration} seconds.`);
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
