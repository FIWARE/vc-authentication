Feature: The vc-authentication component enables the authentication of registered participants.

  Scenario: A registered organization can retrieve a valid access token for its user to access a registered service.
    Given organization is registered in the trusted issuer list.
    When organization issues a credential of type user credential to its user.
    Then the access token retrieved by the user for the registered service is valid.

  Scenario: A registered organization can not retrieve a valid access token for its user to access a registered service when using invalid type of crednetials.
    Given organization is registered in the trusted issuer list.
    When organization issues a credential of type operator credential to its user.
    Then the user is unable to obtain an access token because the credential type is invalid.