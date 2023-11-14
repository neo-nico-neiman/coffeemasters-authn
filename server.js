import express from "express";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import * as url from "url";
import bcrypt from "bcryptjs";
import * as jwtJsDecode from "jwt-js-decode";
import base64url from "base64url";
import SimpleWebAuthnServer from "@simplewebauthn/server";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + "/auth.json");
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static("public"));
app.use(express.json());
app.use(
	express.urlencoded({
		extended: true,
	})
);

function findUser(email) {
	const results = db.data?.users.filter((user) => user.email == email);
	if (results.length == 0) return undefined;
	return results[0];
}

app.post("/auth/login", (req, res) => {
	const { email, password } = req.body;

	const user = findUser(email);
	if (!user) {
		res.status(401).send({ ok: false, message: "Credentials are wrong" });
	}

	if (!bcrypt.compareSync(password, user.password)) {
		res.status(401).send({ ok: false, message: "Credentials are wrong" });
	}

	res
		.status(200)
		.send({ ok: true, user: { name: user.name, email: user.email } });
});

app.post("/auth/auth-options", (req, res) => {
	const foundUser = findUser(req.email);
	if (foundUser) {
		res.send({
			password: !!foundUser.password,
			google: !!foundUser.federated?.google,
			webauthn: !!foundUser.webauthn,
		});
	} else {
		res.status(200).send({ password: true });
	}
});

app.post("/auth/register", (req, res) => {
	const { name, email, password } = req.body;

	if (findUser(email)) {
		res.status(501).send({ ok: false, message: "User already exists" });
	} else {
		//TODO: add validation
		const salt = bcrypt.genSaltSync(10);
		const hashedPassword = bcrypt.hashSync(password, salt);

		const user = {
			name: name,
			email: email,
			password: hashedPassword,
		};

		db.data.users.push(user);
		db.write();

		res.status(200).send({ ok: true, message: "User registered" });
	}
});

app.post("/auth/login-google", (req, res) => {
	let jwt = jwtJsDecode.jwtDecode(req.body.credential);
	let payload = jwt.payload;
	let user = {
		email: payload.email,
		name: payload.given_name + " " + jwt.payload.family_name,
		password: false,
	};
	const userFound = findUser(req.body.email);

	if (userFound) {
		// User exists, we update it with the Google data
		user.federated = { google: payload.aud };
		db.write();
		res.send({ ok: true, name: user.name, email: userFound.email });
	} else {
		// User doesn't exist we create it
		db.data.users.push({
			...user,
			federated: {
				google: payload.aud,
			},
		});
		db.write();
		res.send({ ok: true, name: user.name, email: user.email });
	}
});
app.get("*", (req, res) => {
	res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
