# What this service doesn't do 

 - This is not an Open ID complaint service yet. Open Id is just required to establish the user's identity like name, email etc and that is not the 
   goal of this service. 
 - Doesn't support access to APIs through API keys. This is out of scope. No system to system communication is supported. 


# What this service is intended to do 
 - Role based access system using OAuth specifications
 - Expose an /authorize end point where a front end can redirect to get token and then use that token to get Access and Refresh token. 