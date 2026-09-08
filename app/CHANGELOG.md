# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [1.5.1](https://github.com/UN-OCHA/tools-extract-service/compare/v1.5.0...v1.5.1) (2026-09-08)


### Bug Fixes

* **security:** Bump puppeteer to the current release. ([7385112](https://github.com/UN-OCHA/tools-extract-service/commit/73851121a853692d5ada03039d530f5e6d92517a))
* **security:** Use npn audit fix to bump pakcages with fixes. ([58d7b63](https://github.com/UN-OCHA/tools-extract-service/commit/58d7b63fe7a614b3bfaffe22885566d90f27e1dd))
* build(deps): bump js-yaml and pm2 in /app
* build(deps): bump qs, body-parser and express in /app

## [1.5.0](https://github.com/UN-OCHA/tools-extract-service/compare/v1.4.0...v1.5.0) (2026-08-06)


### Features

* Use federated auth for AWS services. ([5ecd766](https://github.com/UN-OCHA/tools-extract-service/commit/5ecd766e9dedf9983eaab7ef5818399922da3971))


### Bug Fixes

* **security:** Fix outstanding security issues via `audit fix`. ([ce8f6ba](https://github.com/UN-OCHA/tools-extract-service/commit/ce8f6ba0a3aa714a0f93de455dc5b052c6bd42dd))
* **security:** Bump puppeteer to support the latest recommended chromium browser. ([99b8847](https://github.com/UN-OCHA/tools-extract-service/commit/99b8847673b9936dd6a90a4f77a189824504d470))

## [1.4.3](https://github.com/UN-OCHA/tools-extract-service/compare/v1.4.2...v1.4.3) (2026-07-01)

### Bug Fixes

* **security:** Bump puppeteer to cover current chome versions. ([6546169](https://github.com/UN-OCHA/tools-extract-service/commit/6546169a48fb9e909e846674623ca0cca3c8505e))
* **security:** Run `npm audit` to update all packages with fixable security issues. ([3b34a9e](https://github.com/UN-OCHA/tools-extract-service/commit/3b34a9e7a59a2d266488a6c88017d8910d4d95a8))


### [1.4.2](https://github.com/UN-OCHA/tools-extract-service/compare/v1.4.0...v1.4.2) (2026-07-01)


### Bug Fixes

* **bug:** Ensure we skip *ALL* browser downloads by puppeteer. ([7cc5d33](https://github.com/UN-OCHA/tools-extract-service/commit/7cc5d338ccd7315967a59d7fe0fe23850e4d2324))
* **security:** Bump puppeteer to cover current chome versions. ([6546169](https://github.com/UN-OCHA/tools-extract-service/commit/6546169a48fb9e909e846674623ca0cca3c8505e))
* **security:** Bump puppeteer to support the latest recommended chromium browser. ([99b8847](https://github.com/UN-OCHA/tools-extract-service/commit/99b8847673b9936dd6a90a4f77a189824504d470))
* **security:** Run `apm audit fix` to auto-apply security fixes. ([06b6faa](https://github.com/UN-OCHA/tools-extract-service/commit/06b6faa5ffdb4ac8bec2f2052411216520e03819))
* **security:** Run `npm audit` to update all packages with fixable security issues. ([3b34a9e](https://github.com/UN-OCHA/tools-extract-service/commit/3b34a9e7a59a2d266488a6c88017d8910d4d95a8))

### [1.4.1](https://github.com/UN-OCHA/tools-extract-service/compare/v1.4.0...v1.4.1) (2026-06-04)


### Bug Fixes

* **bug:** Ensure we skip *ALL* browser downloads by puppeteer. ([7cc5d33](https://github.com/UN-OCHA/tools-extract-service/commit/7cc5d338ccd7315967a59d7fe0fe23850e4d2324))
* **security:** Bump puppeteer to support the latest recommended chromium browser. ([99b8847](https://github.com/UN-OCHA/tools-extract-service/commit/99b8847673b9936dd6a90a4f77a189824504d470))
* **security:** Run `apm audit fix` to auto-apply security fixes. ([06b6faa](https://github.com/UN-OCHA/tools-extract-service/commit/06b6faa5ffdb4ac8bec2f2052411216520e03819))

### [1.4.0](https://github.com/UN-OCHA/tools-extract-service/compare/v1.3.3...v1.4.0) (2026-05-04)

### Breaking Changes

* Drops support for node <= 16 via pm2.

### Bug Fixes

* **security:** Run `npm audit fix --force` to bump pm2 to the next major. ([260076f](https://github.com/UN-OCHA/tools-extract-service/commit/260076fa4deb2c9207a00ad94264503a64b1a024))
* **security:** Run `npm audit fix` to easily patch known issues. ([252933b](https://github.com/UN-OCHA/tools-extract-service/commit/260076fa4deb2c9207a00ad94264503a64b1a024))
* **security:** Bump puppeteer4 and chromium. ([6c5b15e](https://github.com/UN-OCHA/tools-extract-service/commit/6c5b15e528ac5a30d277df5fb6bd8a2ad472833c))

### [0.0.1]

Cloned from [Snap service](https://github.com/UN-OCHA/tools-snap-service)
