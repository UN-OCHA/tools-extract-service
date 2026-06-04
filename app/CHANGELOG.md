# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [1.4.1](https://github.com/UN-OCHA/tools-extract-service/compare/v1.4.0...v1.4.1) (2026-06-04)


### Bug Fixes

* **bug:** Ensure we skip *ALL* browser downloads by puppeteer. ([7cc5d33](https://github.com/UN-OCHA/tools-extract-service/commit/7cc5d338ccd7315967a59d7fe0fe23850e4d2324))
* **security:** Bump puppeteer to support the latest recommended chromium browser. ([99b8847](https://github.com/UN-OCHA/tools-extract-service/commit/99b8847673b9936dd6a90a4f77a189824504d470))
* **security:** Run `apm audit fix` to auto-apply security fixes. ([06b6faa](https://github.com/UN-OCHA/tools-extract-service/commit/06b6faa5ffdb4ac8bec2f2052411216520e03819))

## [1.4.0](https://github.com/UN-OCHA/tools-extract-service/compare/v1.3.3...v1.4.0) (2026-05-04)

### Breaking Changes

* Drops support for node <= 16 via pm2.

### Bug Fixes

* **security:** Run `npm audit fix --force` to bump pm2 to the next major. ([260076f](https://github.com/UN-OCHA/tools-extract-service/commit/260076fa4deb2c9207a00ad94264503a64b1a024))
* **security:** Run `npm audit fix` to easily patch known issues. ([252933b](https://github.com/UN-OCHA/tools-extract-service/commit/260076fa4deb2c9207a00ad94264503a64b1a024))
* **security:** Bump puppeteer4 and chromium. ([6c5b15e](https://github.com/UN-OCHA/tools-extract-service/commit/6c5b15e528ac5a30d277df5fb6bd8a2ad472833c))

### [0.0.1]

Cloned from [Snap service](https://github.com/UN-OCHA/tools-snap-service)
