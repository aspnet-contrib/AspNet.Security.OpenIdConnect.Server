angular
.module('openiddemoclient')
.controller('NavBarController', NavBarController)

function NavBarController() {



    var access_token, id_token;

    if (window.location.hash) {
        showTokenResponse();
    }

    function showError(error) {
        show(error && error.message || error);
    }

    document.querySelector(".get").addEventListener("click", getToken, false);
    document.querySelector(".validate").addEventListener("click", validateToken, false);
    document.querySelector(".api").addEventListener("click", callApi, false);
    document.querySelector(".logout").addEventListener("click", logout, false);

    function show(data) {
        document.querySelector(".results").textContent += JSON.stringify(data, null, 2);
        document.querySelector(".results").textContent += '\r\n';
    }
    function clear() {
        document.querySelector(".results").textContent = "";
    }
    function rand() {
        return (Date.now() + "" + Math.random()).replace(".", "");
    }

    function showTokenResponse() {
        var hash = window.location.hash.substr(1);
        var result = hash.split('&').reduce(function (result, item) {
            var parts = item.split('=');
            result[parts[0]] = parts[1];
            return result;
        }, {});

        show(result);

        if (result.id_token || result.access_token) {
            id_token = result.id_token;
            document.querySelector("body").className = "token";
        }
    }


    var config = {
        client_id: 'myClient',
        authority: 'http://localhost:54540/',
        redirect_uri: window.location.protocol + "//" + window.location.host + "/index.html",
        post_logout_redirect_uri: window.location.protocol + "//" + window.location.host + "/index.html",
        response_type: "id_token",
        response_type: "id_token token",
        scope: "openid",
        scope: "openid profile email roles",
        scope: "openid profile email roles api1",
        filter_protocol_claims: false,
        filter_protocol_claims: true,
        load_user_profile: false,
        load_user_profile: true,
    };
    var oidc = new OidcClient(config);

    function getToken() {
        oidc.createTokenRequestAsync().then(function (request) {
            console.log(request);
            window.location = request.url;
        }, showError);
    }

    function validateToken() {
        oidc.processResponseAsync().then(function (response) {
            clear();

            //show(response);
            show(response.profile);
            //show("expires_in : " + response.expires_in);

            access_token = response.access_token;
        }, showError);
    }

    function logout() {
        oidc.createLogoutRequestAsync(id_token).then(function (url) {
            window.location = url;
        }, showError);
    }

    function callApi() {
        clear();
        getJson("/api/test", access_token).then(function (response) {
            show(response);
        }, showError);
    }

    function getJson(url, token) {
        return new Promise(function (resolve, reject) {
            var xhr = new XMLHttpRequest();
            xhr.responseType = "json";

            xhr.onload = function () {
                try {
                    if (xhr.status === 200) {
                        var response = xhr.response;
                        if (typeof response === "string") {
                            response = JSON.parse(response);
                        }
                        resolve(response);
                    }
                    else {
                        reject(Error(xhr.statusText + "(" + xhr.status + ")"));
                    }
                }
                catch (err) {
                    reject(err);
                }
            };

            xhr.onerror = function () {
                reject(Error("Network Error"));
            }

            xhr.open("GET", url);

            if (token) {
                xhr.setRequestHeader("Authorization", "Bearer " + token);
            }

            xhr.send();
        });
    }

    var nav = this;



    nav.user = undefined;
    nav.loginUrl = 'http://localhost/123';

    nav.logout = function() {

    }

    nav.login = function() {
        getToken();
    };

}

NavBarController.$inject = [];