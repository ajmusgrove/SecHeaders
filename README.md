# HTTP Security Headers and Content Security Policy plugin for JSP/Servlet Engines

Thix is a plugin for JSP/Servlet engines to dynamically add HTTP security headers
(and actually any headers - I use it for cache headers as well) as well
as build up the Content Security Policy (CSP).

## Key Features

* Rules are applied based on patterns matching hosts, matching URL patterns as well as excluding URL patterns
* The CSP is build up for the entries are progressively added. This gives maximum flexibility and maintainability.
* NONCEs are generated and available for your own code both through ThreadLocal variables and as a request parameter. The length of NONCE is configuration and uses SecureRandom.
* SHA hashs can be added from a seperate file into the CSP in that mode of using strict-dymamic with script-src..
* HTTPS forced redirect can be enabled and restricted to certain hosts.
* A whitelist to ensure no leaks of resources that may be in the archive to the outside world you do not wish to go there. If you ommit the whitelist, this function is inactive.

## Getting Started

To use this plugin, you only need to do the following.

* Copy of the secheaders jar from the dist directory into /WEB-INF/lib
* Add entries in your web.xml to enable the plugin. There is an example at sample/web.xml
* Setup the configuration file, which by default is in /WEB-INF/secheaders.json. A sample is available in sample/secheaders.json.
* Be sure that the gson library is available in the classpath. If it is not, copy the gson jar from lib in this distribution into /WEB-INF/lib. 

## Performance Considerations

The rules in the JSON configuration are run top to bottom and use
pattern matching and other features. This is a complex process
and you might worry it will effect performance. You needn't worry. For
each unique URI the resulting headers and policies are all cached
so, after the first invocation, the cached rule results are used rather than recomputing.

### Depdendencies

The only depdendecy other than the JDK and the Servlet library is GSon for JSON processing. It is provided in the lib directory.

### Configuration Variables in web.xml

There are 3 configuration variables that may be set in the web.xml section for the plugin.

* logger-key - this is the name of the java.util.logging.Logger to use. By default it is com.ajmusgrove.filters.SecHeaders.
* config-file - This is the configuration file. By default it will load the resource as /WEB-INF/secheaders.json. The root is the war root.
* logging-level - this is the logging level to use. If this is not set, the logging configuration operates as normal, which usually means INFO is the level. Generally you want to use the WARN level.

### Using GLOB mattern matching

When matching patterns, the GLOB format is used which operates the same as in bash. Examples are available in the sample configuration. By way of example. *.jsp would match any jsp file.

### Accessing the NONCE

If you are using NONCE values with the CSP as part of a script-src policy of strict-dynamic, as shown in the sample file, a NONCE is generated on each request. It can be accessed one of two ways: either reteive as a request attribute
or from thread local storage.

Request attribute:

```
String nonce = request.getAttribute("_SecHeadersCSPNOnce").toString();
```

From ThreadLocal Storage:

```
String nonce = com.ajmusgrove.filters.SecHeaders.getNOnce();
```

## Built With

* Apache Ant 1.10.1 for build management
* Google GSon for JSON processing

## Tested With

* Tomcat 8.0
* Built with source version set of JDK 1.6, so in theory will work with Tomcat 7

## Authors

* **Arthur J Musgrove** - *Initial work* - ajmusgrove@mac.com www.ajmusgrove.com

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

