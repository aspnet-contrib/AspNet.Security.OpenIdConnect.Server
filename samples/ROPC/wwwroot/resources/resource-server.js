/*global document, XMLHttpRequest */

(function (document, XMLHttpRequest) {

    'use strict';

    var btn,
        token,
        result;

    function authorizedRequest() {

        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onreadystatechange = function () {

            result.innerHTML = "";

            if (xmlhttp.readyState === XMLHttpRequest.DONE) {
                result.innerHTML = xmlhttp.responseText;
            } else if (xmlhttp.status === 400) {
                result.innerHTML = "There was an error 400.";
            } else {
                result.innerHTML = "Something other than 200 returned.";
            }
        };

        xmlhttp.open("GET", "/my-resource-server", true);

        token = document.getElementById("access_token");
        xmlhttp.setRequestHeader("Authorization", "bearer " + token.innerHTML);
        xmlhttp.send();
    }

    btn = document.getElementById("resource-server");
    btn.addEventListener("click", authorizedRequest);

    result = document.getElementById("resource-result");

}(document, XMLHttpRequest));
