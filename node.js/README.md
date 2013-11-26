This is a template for current opinions on good design in node.js.  It pushes everything in to client side and all
node.js work is a REST API for storage and services to the client side 'app'.
Based on instructions at http://www.slideshare.net/fitc_slideshare/building-a-startup-stack-with-angularjs


Edit package.json to name, describe, etc. the project.

Change the cookie secret as well.

To modify things, you may need to install some components globally for ease of access to scripts:
npm install -g express yo generator-webapp generator-angular jasmine-node