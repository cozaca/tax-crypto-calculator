Followed tutorial from:
https://www.bezkoder.com/spring-boot-login-example-mysql/

#How to start the app:
- go under docker directory and run
`docker-compose up`
- like that will deploy a postgres instance and a pgadming instance
- the pgadmin can be reached from browser at : `http://localhost:5050/browser/`
- in order to create a connection we need to specify to pgadmin the address where the 
postgres server is available. In order to find this you need to run in a CMD : `docker inspect ${containerId} | grep IPAddress`
- using the IPAddress resolved before you can create a connection to your DB

# This app is using spring security:
- `https://spring.io/guides/topicals/spring-security-architecture`

## Details about web-security impl used in this app:
    - `@EnableWebSecurity` => allows Spring tot and automatically apply the class to global `WebSecurity`