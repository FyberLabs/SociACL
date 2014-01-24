'use strict';

describe('Controller: MainCtrl', function () {

  // load the controller's module
  beforeEach(module('nodeTemplateApp'));

  var MainCtrl,
    scope;

  // Initialize the controller and a mock scope
  beforeEach(inject(function ($controller, $rootScope) {
    scope = $rootScope.$new();
    MainCtrl = $controller('MainCtrl', {
      $scope: scope
    });
  }));

  it('should attach a list of awesomeThings to the scope', function () {
    expect(scope.awesomeThings.length).toBe(3);
  });
});

//Request URI to translate into resource URI
//Depending on Requester, return different results - none, block, partial block, alternative content, actual content
//none - wrong request
//none - denied request
//none - nothing there anymore
//block - denied request
//block - success request (whatever)
//partial - denied some
//partial - allow all
//alternative content - replacement some
//alternative content - allow all
//actual content - allow all
//actual content - deny all (do we attempt anything else?)

//Support graceful parsing - ie. check each external request or even text for censorable components and remove or swap
//content not revealed
//alternative resource could be limited content, wrong content, request for additional permission/payment

//Blind authorization where a request URI from a known associated service may check a user for permission
//No content manipulating on our side, though we can return a user classification in relation to the request
//or service

//Setup a resource URI with a request URI
//Modify permissions based on groups, logins, etc.

//Check for a persons permissions based on
//verified login ids we know of them
//groups they blong to on social sites - linkedin, facebook, etc.
//location of their app
//additional authentication - multiple factor support - plugins in app and known hashes/certs

//User and group management
//Internal tagging of users and groups - ie. father, girl friend, fellow spy, etc.
//associated service's group creation
//user id and solicitation for login
//custom tagging, but also generic tags/suggestions - father, grandfather, friend, etc.