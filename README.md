# Extract Service

Shared service to extract data out of websites.

## API

You **MUST** use `POST /extract` to request extracts. We do not serve `GET` requests because we want to discourage people hotlinking to extracts, and also to control bot traffic. If you try to `GET /extract` it returns **`HTTP 405 Method Not Allowed`**.

## Headers

- `X-Forwarded-For` — The remote client address making the request. This allows the extract service to log the address.
- `User-Agent` — The remote user-agent of the client making the request. This value is overridden by the `ua` parameter, if present.

## `POST /extract`

|Default  |Required  |Type    |
|---------|----------|--------|
|_null_   |**yes**   |_N/A_   |

### Required Parameters

#### `url`
String representing the URL you want to extract data from.

|Default  |Required  |Type    |
|---------|----------|--------|
|_null_   |**yes**¹  |String  |

The URL must be valid. The protocol must be included. You may not include authentication in the URL (see `user`/`pass` parameters for HTTP Basic Auth).


#### `element`
String representing the element to extract.

|Default  |Required  |Type    |
|---------|----------|--------|
|_null_   |**yes**¹  |String  |


#### `attribute`
String representing the attribute to extract.

|Default  |Required  |Type    |
|---------|----------|--------|
|_null_   |**yes**¹  |String  |

### Optional Parameters

#### `selector`
Specify a CSS selector. Send something very specific, such as an `#html-id`. If you send a generic selector that matches many elements on your page, then extract Service will only return the **FIRST** element that matches your selector.

|Default  |Required  |Type    |
|---------|----------|--------|
|_null_   |no        |String  |
