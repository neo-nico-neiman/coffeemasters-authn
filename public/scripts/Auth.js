import API from "./API.js";
import Router from "./Router.js";

const Auth = {
	isLoggedIn: false,
	account: null,
	postLogin: async (response, credentials) => {
		if (response.ok) {
			Auth.isLoggedIn = true;
			Auth.account = { ...credentials };
			Auth.updateStatus();
			Router.go("/account");
			// Credential management API storage to ahcieve auto login
			if (window.PasswordCredential && credentials.password) {
				const credentialsToStore = new PasswordCredential({
					id: credentials.email,
					password: credentials.password,
					name: credentials.email,
				});

				try {
					navigator.credentials.store(credentialsToStore);
				} catch {
					console.log("Error"); // TODO: improve
				}
			}
		} else {
			alert(response.message);
		}
	},
	autoLogin: async () => {
		if (window.PasswordCredential) {
			const credentials = await navigator.credentials.get({ password: true });
			if (credentials) {
				document.getElementById("login_email").value = credentials.id;
				document.getElementById("login_password").value = credentials.password;
			}
		}
	},
	login: async (event) => {
		event.preventDefault();

		if (Auth.loginStep == 1) {
			Auth.checkAuthOptions();
		}

		if (Auth.loginStep == 2) {
			const credentials = {
				email: document.getElementById("login_email").value,
				password: document.getElementById("login_password").value,
			};

			if (credentials.email && credentials.password) {
				const response = await API.login(credentials);
				Auth.postLogin(response, response.user);
			}
		}
	},
	loginFromGoogle: async (data) => {
		const response = await API.loginFromGoogle(data);
		Auth.postLogin(response, {
			name: response.name,
			email: response.email,
		});
	},
	register: async (event) => {
		event.preventDefault();
		const user = {
			name: document.getElementById("register_name").value,
			email: document.getElementById("register_email").value,
			password: document.getElementById("register_password").value,
		};

		if (user.name && user.email && user.password) {
			const response = await API.register(user);
			if (response.ok) {
			}
		}
	},
	logout: () => {
		Auth.account = null;
		Auth.isLoggedIn = false;
		Auth.updateStatus();
		Router.go("/");

		if (window.PasswordCredential) {
			navigator.credentials.preventSilentAccess();
		}
	},
	updateStatus() {
		if (Auth.isLoggedIn && Auth.account) {
			document
				.querySelectorAll(".logged_out")
				.forEach((e) => (e.style.display = "none"));
			document
				.querySelectorAll(".logged_in")
				.forEach((e) => (e.style.display = "block"));
			document
				.querySelectorAll(".account_name")
				.forEach((e) => (e.innerHTML = Auth.account.name));
			document
				.querySelectorAll(".account_username")
				.forEach((e) => (e.innerHTML = Auth.account.email));
		} else {
			document
				.querySelectorAll(".logged_out")
				.forEach((e) => (e.style.display = "block"));
			document
				.querySelectorAll(".logged_in")
				.forEach((e) => (e.style.display = "none"));
		}
	},
	loginStep: 1,
	checkAuthOptions: async () => {
		const response = await API.checkAuthOptions({
			email: document.getElementById("login_email").value,
		});

		Auth.loginStep = 2;

		if (response.password) {
			document.getElementById("login_section_password").hidden = false;
		}

		if (response.webauthn) {
			document.getElementById("login_section_webauthn").hidden = false;
		}
	},
	init: () => {
		document.getElementById("login_section_password").hidden = true;
		document.getElementById("login_section_webauthn").hidden = true;
	},
};
Auth.updateStatus();
Auth.autoLogin();
export default Auth;

// make it a global object
window.Auth = Auth;
