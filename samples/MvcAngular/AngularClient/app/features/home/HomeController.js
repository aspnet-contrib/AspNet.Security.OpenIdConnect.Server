angular
    .module('openiddemoclient')
    .controller('HomeController', HomeController);

function HomeController() {
    var vm = this;

    vm.user = 123;
    vm.loginUrl = 'http://localhost/123';

    vm.logout = function() {

    }
}

HomeController.$inject = [];

