const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", function (req, res) {
	const client_id = req.query.client_id;
	const client = clients[client_id];
	if (client) {
		const scopes = req.query.scope.split(" ");
		if (containsAll(client.scopes, scopes)) {
			const requestId = randomString();
			requests[requestId] = req.query;
			const renderOptions = { client, scope: req.query.scope, requestId };
			return res.render("login", renderOptions, function (err, html) {
				res.send(html);
			});
		}
	}
	res.sendStatus(401);
});

app.post("/approve", function (req, res) {
	const userName = req.body.userName;
	const password = req.body.password;
	if (users[userName] === password) {
		const requestId = req.body.requestId;
		const request = requests[requestId];
		if (request) {
			delete requests[requestId];
			const authKey = randomString();
			authorizationCodes[authKey] = { clientReq: request, userName };
			const redirectUrl = new URL(request.redirect_uri);
			redirectUrl.searchParams.append("code", authKey);
			redirectUrl.searchParams.append("state", request.state);
			return res.redirect(redirectUrl);
		}
	}
	res.sendStatus(401);
})

app.post("/token", function (req, res) {
	const authorization = req.headers.authorization;
	if (authorization) {
		const decodedCreds = decodeAuthCredentials(authorization);
		const clientId = decodedCreds.clientId;
		const client = clients[clientId];
		if (client) {
			const clientSecret = decodedCreds.clientSecret;
			if (client.clientSecret === clientSecret) {
				const code = req.body.code;
				const obj = authorizationCodes[code];
				if (obj) {
					delete authorizationCodes[code];
					const jwtObj = {
						userName: obj.userName,
						scope: obj.clientReq.scope
					};
					const privateKey = fs.readFileSync("assets/private_key.pem");
					const jwtResponse = jwt.sign(jwtObj, privateKey, { algorithm: 'RS256' });
					return res.json({ access_token: jwtResponse, token_type: "Bearer" });
				}
			}
		}
	}
	res.sendStatus(401);
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
