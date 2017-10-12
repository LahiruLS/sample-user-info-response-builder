# sample-user-info-response-builder
This sample response builder (`SampleResponseBuilder`) for userinfo endpoint is an implementation of 
`org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder`.

The extension executes while building the response for `userinfo` endpoint. The `SampleResponseBuilder` adds the 
capability to filter the claims returned by the userinfo endpoint based on service provider's requested claims.

## Building the source

### Pre requisites

1. JDK 1.7
2. maven 3.x.x

Build the project by running  `mvn clean install` on the project home (directory where pom.xml is).

## Deploying the sample

1. Copy `user-info-1.0.0-SNAPSHOT.jar` from `<project_home>/target` to `<is_home>/repository/components/lib` directory.
2. In the `<is_home>/repository/conf/identity.xml` file, replace following config. The `<UserInfoEndpointResponseBuilder>` represents 
the fully qualified class name of the custom `UserInfoResponseBuilder`.

```xml
<OAuth>
...
  <OpenIDConnect>
  ...
    <UserInfoEndpointResponseBuilder>sample.json.response.builder.user.info.SampleResponseBuilder</UserInfoEndpointResponseBuilder>
  ...
```

3. Restart Identity Server.

