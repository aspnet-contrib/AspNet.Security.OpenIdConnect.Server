var helpers = (function () {

    'use strict';

    var module = {};

    module.makeFriendlyString = function makeFriendlyString(obj) {
        var i,
            keys,
            key,
            value,
            friendlyString;

        keys = Object.keys(obj);

        friendlyString = "<dl>";
        for (i = 0; i <= keys.length; i += 1) {
            key = keys[i];
            value = obj[key];

            friendlyString += "<dt>" + key + "</dt><dd id='" + key + "'>" + value + "</dd>";
        }
        friendlyString += "</dl>";

        return friendlyString;
    };

    return module;

}());