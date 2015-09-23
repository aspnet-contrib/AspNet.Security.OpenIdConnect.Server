angular
    .module('openiddemoclient')
    .config(['$routeProvider',
        function ($routeProvider) {
            $routeProvider.
                when('/', {
                    templateUrl: 'features/home/home.html',
                    controller: 'HomeController',
                    controllerAs: 'vm'
                }).
                when('/apicall' ,{
                    templateUrl: 'features/apicall/apicall.html',
                    controller: 'ApiCallController',
                    controllerAs: 'vm'
                }).
                otherwise({
                    redirectTo: '/'
                });
        }]
);
