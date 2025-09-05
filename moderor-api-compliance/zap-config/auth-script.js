/**
 * ZAP Authentication Script for API Testing
 * This script demonstrates how to configure authentication for API security testing
 */

// Example authentication script for Bearer token authentication
function authenticate(helper, paramsValues, credentials) {
    // Extract credentials
    var username = paramsValues.get("Username");
    var password = paramsValues.get("Password");

    // Perform authentication request (customize based on your API)
    var loginUrl = paramsValues.get("Login URL") || "http://localhost:8001/api/auth/token/";
    var loginRequest = 'POST ' + loginUrl + ' HTTP/1.1\r\n' +
                      'Host: localhost:8001\r\n' +
                      'Content-Type: application/json\r\n' +
                      'Content-Length: ' + JSON.stringify({
                          username: username,
                          password: password
                      }).length + '\r\n\r\n' +
                      JSON.stringify({
                          username: username,
                          password: password
                      });

    // Send authentication request
    var response = helper.sendAndReceive(loginRequest);

    // Extract token from response (customize based on your API response format)
    var responseBody = response.getBody().toString();
    var tokenMatch = responseBody.match(/"access"\s*:\s*"([^"]+)"/);

    if (tokenMatch && tokenMatch[1]) {
        var token = tokenMatch[1];

        // Set authorization header for subsequent requests
        helper.addAuthHeader("Authorization", "Bearer " + token);

        // Store token for reuse
        helper.setAuthToken(token);

        return response;
    } else {
        throw new Exception("Authentication failed - could not extract access token");
    }
}

function getRequiredParamsNames(){
    return ["Username", "Password", "Login URL"];
}

function getOptionalParamsNames(){
    return ["Realm", "Port"];
}

function getCredentialsParamsNames(){
    return ["Username", "Password"];
}

// Example for Basic Authentication
function authenticateBasic(helper, paramsValues, credentials) {
    var username = paramsValues.get("Username");
    var password = paramsValues.get("Password");

    // Create Basic auth header
    var auth = "Basic " + helper.base64Encode(username + ":" + password);
    helper.addAuthHeader("Authorization", auth);

    return null; // No response needed for Basic auth
}

/**
 * Usage Instructions:
 *
 * 1. Copy this script to your ZAP scripts directory
 * 2. Modify the authentication logic based on your API's auth mechanism
 * 3. Configure the authentication in ZAP:
 *    - Tools → Options → Authentication
 *    - Select "Script-based Authentication"
 *    - Choose this script
 *    - Configure the required parameters
 *
 * 4. Set up the authentication context:
 *    - Right-click on a request → Include in Context
 *    - Configure authentication for the context
 *
 * 5. The script will automatically authenticate before scans
 */

/**
 * Supported Authentication Types:
 *
 * 1. Bearer Token (JWT)
 * 2. Basic Authentication
 * 3. API Key Authentication
 * 4. OAuth 2.0
 * 5. Custom Authentication
 *
 * Customize the authenticate() function based on your API's authentication method.
 */
