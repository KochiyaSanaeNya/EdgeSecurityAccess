# EdgeSecurityAccess
- WireGuard-based rapid networking software  
  This software has not undergone complete software usability testing and production deployment testing, and is strongly discouraged for commercial use or scenarios requiring high stability.  
  Code security and quality are reviewed and approved by AI.  
  **NOTICE** This project uses artificial intelligence to assist development during the development stage  
  This server software suite is designed specifically for the Linux operating system.  
  [Notice Board](https://blog.sanaenya.com/esa)  
  [Development Updates](https://esadevstatus.122244.xyz)  
  **TODO List:**

- [x] Encrypt username and password.  

- [x] The parsing issue of SplitN in usercfg.go.  

- [x] No verification was performed on the IP address or WireGuard key.  

- [x] Architectural risk: User keys are stored on the server (this issue will be resolved in the next software refactoring).  

- [x] The goroutine's main loop may be blocked.  

- [ ] There is no proper logging and error reporting system.  

- [ ] Fail2ban is not integrated to protect users.  

- [x] Unable to obtain the real IP in reverse proxy scenarios.  
  **These issues will be fixed within a few version updates.**  
  **ESATools will be integrated into this repository.**  
  [Manual of EdgeSecurityAccess (Part I - Basic usage v26.5.1x Version)](https://blog.sanaenya.com/archives/manual-of-edgesecurityaccess-part-i---basic-usage)  

  

