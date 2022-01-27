import jwt from 'jsonwebtoken';

/**
 * This is a utility class that checks the HTTP header for a "Bearer: JWT" and compares the JWT validity against
 * the Twilio API Key Secret. This is because Twilio JWTs are created using and API Key Secret, so a good way to secure
 * a client bearer on the server side.
 * 
 * Constructor:
 * @param {string} headers - The HTTP headers containing authorization information.
 * @param {string} secret - The Twilio API Key Secret.
 * 
 */
export default class CheckBearer {
    constructor(headers = {}, secret = "") {
        super();
        this.headers = headers;
        this.secret = secret;
    }

    verifyBearer() {
        // Grab the auth token from the request header
        const authHeader = this.headers.authorization;

        // Reject requests that don't have an Authorization header
        if (!authHeader)
            return { valid: false, error: 'no auth header present' };

        // The auth type and token are separated by a space, split them
        const [authType, authToken] = authHeader.split(' ');
        // If the auth type is not Bearer, return false
        if (authType.toLowerCase() !== 'bearer')
            return { valid: false, error: 'no bearer token' };

        try {
            // Verify the token against the secret. If the token is invalid, jwt.verify will throw an error and we'll proceed to the catch block
            jwt.verify(authToken, this.secret,);
            // At this point, the request has been validated and you could do whatever you want with the request.
            return { valid: true, error: null };
        } catch (error) {
            // If an error was thrown, the token is invalid.
            return { valid: false, error: `Invalid JWT token with error ${JSON.stringify(error, null, 4)}` };
        }
    };
}

//"type": "module",