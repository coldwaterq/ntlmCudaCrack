# ntlmCudaCrack

This is currently slower than running hashcat, but it's a fun project to experiment with. This takes 1 hour 22 minutes, on a gpu that hashcat takes ~30 minutes.

hacked together from the Nvidia vectorAdd sample and https://openwall.info/wiki/john/NTLM

Only chracks a 7 char password, and is hard coded to run the debug function. This is very much not a final product.