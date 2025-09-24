I found existing delegation checking tools kinda suck! 

This machine has protocol transmission, but this popular tool doesn't pick up on it! 
findDelegation.py 'whiterock.local/svc-app$' -dc-ip 10.0.17.112 -hashes :327d57fda899f1f298b8ac422833341e 

AccountName  AccountType                          DelegationType  DelegationRightsTo                    SPN Exists 
-----------  -----------------------------------  --------------  ------------------------------------  ----------
svc-app$     ms-DS-Group-Managed-Service-Account  Constrained     ldap/EC2AMAZ-N5NM90M.whiterock.local  Yes        
svc-app$     ms-DS-Group-Managed-Service-Account  Constrained     host/EC2AMAZ-N5NM90M.whiterock.local  Yes        


So, instead you should run a raw ldapsearch, right? 

ldapsearch -H ldaps://EC2AMAZ-N5NM90M.whiterock.local -D 'WHITEROCK\temp-it-user' -w 'Password123!' -b 'DC=whiterock,DC=local' '(sAMAccountName=svc-app$)' userAccountControl msDS-AllowedToDelegateTo

Here, we see an output: 
userAccountControl: 17305600
msDS-AllowedToDelegateTo: ldap/EC2AMAZ-N5NM90M.whiterock.local
msDS-AllowedToDelegateTo: host/EC2AMAZ-N5NM90M.whiterock.local
msDS-AllowedToDelegateTo: cifs/EC2AMAZ-N5NM90M.whiterock.local

WTF does that UserAccountControl value mean though? Very tedious to manually decode, thus, this tool was born... 

<img width="882" height="539" alt="image" src="https://github.com/user-attachments/assets/019d78bb-f0b1-4136-893a-075678437555" />
