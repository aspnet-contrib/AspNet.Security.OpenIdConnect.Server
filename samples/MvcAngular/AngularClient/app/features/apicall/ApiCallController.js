angular
    .module('openiddemoclient')
    .controller('ApiCallController', ApiCallController);

function ApiCallController(ApiCallService) {
    var vm = this;
    vm.successMessage = '';
    vm.errorMessage = '';

    vm.callApi = function () {
        ApiCallService.callApi()
            .then(function (response) {
                if(response.status===401) {
                    vm.successMessage = '';
                    vm.errorMessage = 'Sign in first!';
                }
                else {
                    vm.successMessage = response.data;
                    vm.errorMessage = '';
               }
            })

    }
}

ApiCallController.$inject = ['ApiCallService'];

angular
    .module('openiddemoclient')
    .factory('ApiCallService', ApiCallService)

function ApiCallService($http) {


    var factory = {};

    factory.callApi = function () {
        return $http.get('http://localhost:54540/api/message')
    };

    return factory;
}

ApiCallService.$inject = ['$http'];