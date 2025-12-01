function AdeleAuth(configuration){

    // configuration
    this.authorizationEndpointUri = configuration.authorizationEndpointUri ? configuration.authorizationEndpointUri : "/oauth/authorize",
    this.clientId = configuration.clientId // Your OAuth client ID
    this.grantType = configuration.grantType
    this.issuer = configuration.issuer // The authentication server
    this.redirectUri = configuration.redirectUri // Your registered redirect URI  to return the user to after authorization is complete
    this.responseType = 'code', // indicates that your server expects to receive an authorization code
    this.scopes = configuration.scopes ? configuration.scopes : ""
    this.tokenEndpointUri = configuration.tokenEndpointUri ? configuration.tokenEndpointUri : "/oauth/token"
    this.challengeCodeMethod = "S256"

    // internal token manger for working with tokens
    this.tokenManager = {
        // Store a value in the token manager. If the value is an object, it is converted to JSON before. Other types are stored directly as a string
        add: async (key, value) => {
            if (typeof value === 'object') {
               localStorage.setItem(key, JSON.stringify(value));
            } else {
                localStorage.setItem(key, value);
            }
        },
        // Clear all items from the token manager
        clear: async () =>{
            localStorage.clear()
        },
        // Get a item from the token manger by its key. if the is found and it is an object, JSON is returned, otherwise the value is returned as a string.
        get: async (key) =>{
            const value = localStorage.getItem(key);
            try {
                return JSON.parse(value);
            } catch (e) {
                return value;
            }
        },
        // Remove an item from the token manager by its key
        remove: async (key) =>{
            localStorage.removeItem(key)
        }
    }
    this.token = {
        generateCodeVerifier: () => {
            // unreserved character that can make up a random STRING per RFC3986 Section 2.3
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

            try {
            // Generate random length between 43 and 128 inclusive
            const lengthArray = new Uint16Array(1);
            window.crypto.getRandomValues(lengthArray);
            let length = Math.min(lengthArray[0] % (128 - 43) + 43, 128);

            let verifier = '';

            // Generate the code verifier string
            for (let i = 0; i < length; i++) {
                const randomIndex = new Uint8Array(1);
                window.crypto.getRandomValues(randomIndex);
                verifier += characters[Math.floor((randomIndex[0] / 255) * characters.length)];
            }

            return verifier

            } catch (error) {
                console.error('Failed to generate code verifier:', error);
                return null; // or throw an error
            }
        },
        /**
         * Create a code challenge derived from the code verifier by using S256.
         * @param {string} verifier - The code verifier string to be transformed into a code challenge.
         * @returns {string} The code challenge derived from the code verifier.
         * @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
         */
        generateCodeChallenge: async (verifier) => {
            try{
                if (!verifier) {
                    return null;
                }

                // Convert the code verifier to a ArrayBuffer
                const verifierEncoder = new TextEncoder().encode(verifier)

                // Generate SHA-256 digest of the code verifier
                const hashBuf = await crypto.subtle.digest('SHA-256', verifierEncoder)

                // Convert to a base64 string
                const hashB46 = btoa(String.fromCharCode(... new Uint8Array(hashBuf)))
                .replace(/\//g, '_')
                .replace(/\+/g, '-')
                .replace(/=/g, '')

                return hashB46
            }
            catch(error){
                console.error('Error during code challenge creation:', error);
            }
        },
        /**
         * Create a random string that will be used by the client to verify state. The state is sent during
         * the initial authorization request and sent back from the authorization server.
         * @returns {string} The state string
         */
        generateStateVerifier: async () => {
            const randomBytes = new Uint8Array(16);
            window.crypto.getRandomValues(randomBytes);

            // Convert bytes to a URL-safe base64 string
            let state = btoa(String.fromCharCode.apply(null, randomBytes));

            // Replace '+' with '-' and '/' with '_' to make it URL-safe
            state =  btoa(state.replace(/\+/g, '-').replace(/\//g, '_'))

            return state;
        },
        getWithoutRedirect: async () => {
             try{

                const codeVerifier = await adeleAuth.token.generateCodeVerifier()
                const codeChallenge = await adeleAuth.token.generateCodeChallenge(codeVerifier)
                const stateVerifier = await adeleAuth.token.generateStateVerifier(codeVerifier)

                // store tokens for verification
                adeleAuth.tokenManager.add("verifier", codeVerifier)
                adeleAuth.tokenManager.add("state", stateVerifier)

                // Request parameters
                const params = new URLSearchParams({
                    client_id: this.clientId,
                    grant_type: "authorization_code",
                    response_type: this.responseType,
                    redirect_uri: encodeURIComponent(this.redirectUri),
                    state: stateVerifier,
                    code_challenge: codeChallenge,
                    code_challenge_method: this.challengeCodeMethod,
                    scopes: this.scopes
                })

                const queryString = new URLSearchParams(params).toString();
                const serverUrl = this.issuer + this.authorizationEndpointUri +"?"+ queryString.toString()


                // Make the POST request using Fetch API
                const response = await fetch(serverUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept' : 'application/json'
                    },
                    body: params.toString()
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`)
                }

                const tokenResponse = await response.json()

                if (tokenResponse.state != stateVerifier) {
                    throw new Error(`HTTP error! the state returned from the authorization server was invalid`);
                }

                adeleAuth.tokenManager.add("type", tokenResponse.token_type)
                adeleAuth.tokenManager.add("code", tokenResponse.code)

            } catch (error) {
                console.error('Error during authorization request:', error);
            }
        },
        /**
         * Sends the code challenge as part of the OAuth 2.0 Authorization Request (Section 4.1.1 of [RFC6749]) using the
         * code_challenge and code_challenge_method parameters to the Authorization Server.
         * @param {string} verifier - The code verifier string to be transformed into a code challenge.
         * @returns {string} The authorization code from the authorization server
         * @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
         */
        getWithRedirect: async () => {
            try{
                const codeVerifier = await adeleAuth.token.generateCodeVerifier()
                const codeChallenge = await adeleAuth.token.generateCodeChallenge(codeVerifier)
                const stateVerifier = await adeleAuth.token.generateStateVerifier(codeVerifier)

                // store tokens for verification
                adeleAuth.tokenManager.add("verifier", codeVerifier)
                adeleAuth.tokenManager.add("state", stateVerifier)

                // Request parameters
                const params = new URLSearchParams({
                    client_id: this.clientId,
                    grant_type: "authorization_code",
                    response_type: this.responseType,
                    redirect_uri: encodeURIComponent(this.redirectUri),
                    state: stateVerifier,
                    code_challenge: codeChallenge,
                    code_challenge_method: this.challengeCodeMethod,
                    scopes: this.scopes
                })

                // Your OAuth server's token endpoint URLc
                const queryString = new URLSearchParams(params)
                const serverUrl = this.issuer + this.authorizationEndpointUri +"?"+ queryString.toString()
                window.location = serverUrl
            } catch (error) {
                console.error('Error during authorization request:', error);
            }
        },
        /**
         * Sends the Authorization Code and the Code Verifier to the Token Endpoint to exchange for a access token.
         * @returns access token for making authenticated calls to the server
         * @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
         */
        doTokenRequest: async () => {
            try{
                const serverUrl =  this.issuer + this.tokenEndpointUri
                const authorization = async function(){
                    const queryString = window.location.search;
                    const urlParams = new URLSearchParams(queryString);
                    const paramCode = urlParams.get('code') ? urlParams.get('code') : await adeleAuth.tokenManager.get("code")
                    if(paramCode == null){
                        throw new Error("Unable to obtain authorization code from the authorization server.")
                    }
                    return paramCode
                }()

                // Request parameters
                const params = new URLSearchParams({
                    code: await authorization,
                    client_id: this.clientId,
                    code_verifier: await adeleAuth.tokenManager.get("verifier"),
                    code_challenge_method: this.challengeCodeMethod,
                    grant_type: "resource_owner_password_credentials",
                    scopes: this.scopes,
                })

                // Make the POST request using Fetch API
                const response = await fetch(serverUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept' : 'application/json'
                    },
                    body: params.toString()
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const tokenResponse = await response.json()
                adeleAuth.tokenManager.add("type", tokenResponse.token_type)
                adeleAuth.tokenManager.add("token", tokenResponse.access_token)
                adeleAuth.tokenManager.add("refresh", tokenResponse.access_token)
                adeleAuth.tokenManager.add("expiry", tokenResponse.expires_in)

            } catch (error) {
                console.error('Error during authorization request:', error);
            }
        }
    }
}
