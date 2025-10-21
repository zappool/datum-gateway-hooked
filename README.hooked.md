# DATUM Gateway with hooks

A hook is added for accepted work.
Prototype, work-in-progress.


## New config elements

- Upstream username: The username of the proxy pool at the upstream pool (at Ocean it is a bitcoin address, "bc1xxxsomething..."). Proxy usernames are converted to this when forwarded to the upstream pool.

- Workstat service URL: This is an accessible API which is invoked with every accepted work share.

```
	"proxypool": {
		"upstream_username": "bc1xxxsomething",
		"workstat_api_url": "http://localhost:5000/api/"
	}
```


## Username mapping

The incoming usernames are changed to the upstream username of the proxy pool.

For usernames with optional device names, a unique device name is used, to keep device shares separate. The device ID is generated deterministically from the hash of the original full username.

Mapping examples:

```
	npub12gygh77v0ux4xk73vvht34lf3g8hs3vfsdjs823ts6pce9n28ehq8edvt8             -->    bc1q98wufxmtfh5qlk7fe5dzy2z8cflvqjysrh4fx2
	npub12gygh77v0ux4xk73vvht34lf3g8hs3vfsdjs823ts6pce9n28ehq8edvt8.bitaxe      -->    bc1q98wufxmtfh5qlk7fe5dzy2z8cflvqjysrh4fx2.8c65fb71
```


## Workstat service

The workstat service is used to pass information about each accepted work share.

The API is called `work-insert`, with HTTP POST, and is supplied with Json-formatted data containing:

- the usernames (original and mapped), and

- the difficulty of the work.

Example:

```json
  {
    "uname_o": "npub12gygh77v0ux4xk73vvht34lf3g8hs3vfsdjs823ts6pce9n28ehq8edvt8",
    "uname_u": "bc1q98wufxmtfh5qlk7fe5dzy2z8cflvqjysrh4fx2",
    "tdiff": 131072
  }
```

See https://github.com/zappool/zappool-backend/tree/main/workstat for an implementation example.


## To generate diff file:

git diff <commit>
git diff cd7b7a3
