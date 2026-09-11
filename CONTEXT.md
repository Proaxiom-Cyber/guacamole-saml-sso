# Guacamole deployments

This context describes Guacamole deployments for temporary customer project access
and ongoing use. IT administrators provision and remove these deployments.

## Language

**Deployment**:
One Guacamole installation and the resources that support it.
_Avoid_: Environment, when referring to one installation

**Temporary deployment**:
A deployment for a limited purpose, such as access to customer infrastructure during
a project.
_Avoid_: Test deployment, because temporary project access can serve real work

**Durable deployment**:
A deployment intended to provide an ongoing service.
_Avoid_: Permanent deployment, because it can still be removed

**Created resource**:
A resource that the deployment tool created for a deployment. Creation makes it
eligible for consideration during teardown, but does not resolve later dependencies.
_Avoid_: Matching resource, because a matching name does not establish creation

**Pre-existing resource**:
A resource that existed before the deployment tool used it. The tool must not offer
this resource for deletion during teardown.
_Avoid_: Created resource, when the tool only reused an existing resource

**Teardown**:
The guided removal of resources that the deployment tool created for a deployment.
_Avoid_: Reset, because resetting application data is a different operation
