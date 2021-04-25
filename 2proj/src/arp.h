struct	arp	{
	short	ar_hwtype;
	short	ar_prtype;
	char	ar_hwlen;
	char	ar_prlen;
	short	ar_op;
	char	ar_srcmac[6];
    char    ar_srcip[4];
    char    ar_dstmac[6];
    char    ar_dstip[4];    
};