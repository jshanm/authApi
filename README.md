# authApi
Library to enable Token authentication to REST Services

Add the excluded path like this.  
authentication:  
  exclude:  
      - /v2/api-docs  
      - /swagger-resources/**  
      - /swagger-ui.html  
      - /configuration/**  
      - /webjars/**  
      - /public  
      - /favicon.ico  
      - /users/signup  

TODO:
 1.  Header configuration - Configure the header where the token would be reeceuved  
 2. How to support both acces and Id Token.
 3. Return back the puaid (or the `sub` of the token)
