# Contributing Guidelines

| Audience |
| :------- |
| Everyone |

This file contains some instructions for installing, developing for, and preparing releases for the Shared extract Service. Each section is marked with an Audience to help you decide whether the docs are for your current task.


## Install / Develop locally

| Audience     |
| :----------- |
| Contributors |

The node container will do all the npm installation for you. No need to do it locally. Just run the Docker commands to get started.

```sh
# set BASEDIR and ALLOWED_HOSTNAMES and tweak MAX_CONCURRENT_REQUESTS for your hardware
vim .env
docker-compose build

# Start the container
docker-compose up
```

Now you can `POST` to `localhost:8442/extract` and it should return extracts to you. There's also a `/status` route for pingdom that you can `GET` in order to quickly confirm it's up and running and not at its concurreny limit:

```sh
# Ping the service to confirm server is running. HTTP 200 is success, the response body shows the number of in-flight extract requests.
curl -X GET http://localhost:8442/status

# Extract a PDF of example.com and save to tmp.pdf
curl -X POST 'http://localhost:8442/extract?url=https://example.com&service=test'
```

It will probably be necessary to use an app that helps you formulate and store common queries you want to test. Command line tools like `curl` are perfectly capable, but if you want something more visual try [Insomnia](https://insomnia.rest/). It lets you configure everything and save each query for repeated use.


### Lint the codebase locally

Travis will lint the codebase on every PR, but you can run it locally ahead of time:

```sh
# Lint the codebase
docker-compose exec extract npm run lint
```


## Monthly Chromium upgrades

| Audience    |
| :---------- |
| Maintainers |

Right now, the process requires manual verification by a human. Please follow these steps to upgrade Chromium and ensure that the same release will be available for testing in our infrastructure.

1. [Check Chromium version](#1-check-chromium-version)
2. [Check Puppeteer version](#2-check-puppeteer-version)
3. [Update dependencies](#3-update-dependencies)
4. [Create commit message for CHANGELOG](#4-create-commit-message-for-changelog)
5. [Release and verify that Docker image is available](#5-release-and-verify-that-docker-image-is-available)

### 1. Check Chromium version

Whenever you build a new Docker image for extract, the version of Chromium is dynamically fetched from Google servers. You can do this at any time on your local machine by running the following command from the repo root:

```sh
docker-compose build --no-cache
```

Watch the console output and note the STABLE version of Chrome as the logs stream by. It can help to highlight the whole log block and once you see it, copy the text as quickly as you can. There might be a smarter way to do this, but copying logs is reliable enough. Example of the log you're looking for:

![extract logs](https://user-images.githubusercontent.com/254753/120500125-e64ee780-c3c0-11eb-8e23-0603c1c733ef.png)

### 2. Check Puppeteer version

Once you have the stable version of Chromium identified, visit https://pptr.dev/chromium-support to view the official Puppeteer releases and corresponding Chromium versions. You'll want to select the version of Puppeteer that is closest to the stable release you noted in the previous step. In this example case from July 2022, the two versions are:

- Chromium: 103.0.5060.114-1
- Puppeteer 14.2.0, which expects Chromium 103.0.5059.0

### 3. Update dependencies

Once the Puppeteer version is noted, go and manually update `app/package.json` inside the repo to ensure Puppeteer will have the correct version installed, then run one the following commands to ensure the codebase is fully updated and working like normal:

```sh
# Start extract Service in case the container isn't running
docker-compose up

# Use npm to install after having manually edited
# app/package.json to the desired version of Puppeteer.
docker-compose exec extract npm install

# If you want to be really safe, restart the container.
docker-compose restart extract

# Output the version of Puppeteer extract is using.
docker-compose exec extract npm ls puppeteer
```

**NOTE:** Nowadays, the breaking changes are listed under `puppeteer-core` in the repo's releases list. An example is `22.0.0` which took away `browser.createIncognitoBrowsercontext` and replaced with `browser.createBrowserContext` (same functionality).

### 4. Create commit message for CHANGELOG

**Based on how the upgrades affect end users of extract**, pick an appropriate [commit message](#commit-messages).

Now you can run some local tests using either cURL (see installation section) or another tool of your choice, with [the API docs](README.md) as your guide to craft the requests.

To help highlight the security-related nature of your updates, you'll most often use the keyword `fix` along with a component of `security` like so:

```sh
git cm -m "fix(security): update Chromium/puppeteer"
```

This will cause it to be listed in the CHANGELOG as a security fix.

### 5. Release and verify that Docker image is available

_Note: Since the Chromium version is dynamically fetched at image build time, **the work is not finalized until a release has been tagged and built by our Docker container repository**. Ideally, the tag should be created as soon as dev is considered to be stable, i.e. within an hour of the dev deploy. Then you have the exact same version of Chromium in the prod release as the untagged dev deploy._

Create a new branch from `dev` and run the release command to generate the new CHANGELOG and increment the version number in our `package.json` and other related files. There's a dry-run flag to preview what will happen:

```sh
# Example with the dry-run flag.
$ npm run release -- --dry-run

> tools-extract-service@3.0.0 release
> standard-version "--dry-run"

✔ bumping version in package.json from 3.0.0 to 3.0.1
✔ bumping version in package-lock.json from 3.0.0 to 3.0.1
✔ outputting changes to CHANGELOG.md
```

The command to make a release contains no flags:

```sh
$ npm run release
```

Review the commit and make any necessary adjustments to the CHANGELOG, using `git commit --amend` to add your changes to the existing commit that `standard-version` just created. Push your branch and open a PR to `dev`, which you can merge without review.

[Create the new Release][new-release] using the GitHub UI with the following properties:

- **Tag:** new tag with format `v0.0.0` — numbers should match [`package.json` in the `dev` branch][dev-package].
- **Target branch:** `dev`
- **Title:** `Production YYYY-MM-DD` using the PROD date (it's normally the coming Thursday)
- **Release notes:** Copy the new CHANGELOG bullets. If dependabot made any updates during this cycle, you can include "regular security updates" without being specific.

Once the tagged Release has been created, [create a PR from `dev` to `master`][pr-dev-master] which will include all work within the tagged release. You can merge that without review as well. This step allows hotfixes to be created from `master` should the need arise.

  [pr-dev-master]: https://github.com/UN-OCHA/tools-extract-service/compare/master...dev
  [new-release]: https://github.com/UN-OCHA/tools-extract-service/releases/new?target=dev
  [dev-package]: https://github.com/UN-OCHA/tools-extract-service/blob/dev/app/package.json#L4


## Commit messages

| Audience     |
| :----------- |
| Contributors |

As of `v2.7.3` we are using [standard-version](https://github.com/conventional-changelog/standard-version#standard-version) to generate a `CHANGELOG.md` for each release. This automation is only possible if our commits follow the [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/).

Here are a few brief examples:

```sh
#
# All examples assume you're on version 4.0.0 when creating the example commit.
#

# a normal bugfix
# Outcome: new patch version (4.0.1)
git cm -m "fix: remove typo from error message"

# a new feature that relates to "pdf"
# Outcome: new minor version (4.1.0)
git cm -m "feat(pdf): add new param for PDF generation"

# a bugfix that creates a breaking change
# Outcome: new major version (5.0.0)
git cm -m "fix!: remove legacy params from PDF generation

Refs: ABC-XXXX
BREAKING CHANGE: we had some special cases which are no longer necessary now
that all extract sites are migrated to property X. Therefore we are removing our
deprecated PDF params."

# Regularly scheduled Chromium/puppeteer upgrade
# Outcome: new patch version (4.0.1)
git cm -m "fix(security): update Chromium/puppeteer"
```
