--- dhcp6c_script.c.orig	2016-12-19 08:16:42 UTC
+++ dhcp6c_script.c
@@ -71,6 +71,8 @@ static char nispserver_str[] = "new_nisp
 static char nispname_str[] = "new_nisp_name";
 static char bcmcsserver_str[] = "new_bcmcs_servers";
 static char bcmcsname_str[] = "new_bcmcs_name";
+static char reason[32];
+
 
 int
 client6_script(scriptpath, state, optinfo)
@@ -78,20 +80,44 @@ client6_script(scriptpath, state, optinf
 	int state;
 	struct dhcp6_optinfo *optinfo;
 {
-	int i, dnsservers, ntpservers, dnsnamelen, envc, elen, ret = 0;
+	int i,z, dnsservers, ntpservers, dnsnamelen, envc, elen, ret = 0;
 	int sipservers, sipnamelen;
 	int nisservers, nisnamelen;
 	int nispservers, nispnamelen;
 	int bcmcsservers, bcmcsnamelen;
 	char **envp, *s;
-	char reason[] = "REASON=NBI";
 	struct dhcp6_listval *v;
 	pid_t pid, wpid;
-
+	
+	switch(state) {
+	  case DHCP6S_INFOREQ:
+	    sprintf(reason,"REASON=INFO");
+	    break;
+	  case DHCP6S_REQUEST:
+	    sprintf(reason,"REASON=REPLY");
+	    break;
+	 case DHCP6S_RENEW:
+	    sprintf(reason,"REASON=RENEW");
+	    break;
+	case DHCP6S_REBIND:
+	    sprintf(reason,"REASON=REBIND");
+	    break;
+	case DHCP6S_RELEASE:
+	    sprintf(reason,"REASON=RELEASE");
+	    break;
+	case DHCP6S_EXIT:
+	    sprintf(reason,"REASON=EXIT");
+	    break;  
+	default:
+	    sprintf(reason,"REASON=OTHER");
+	}
+	
 	/* if a script is not specified, do nothing */
 	if (scriptpath == NULL || strlen(scriptpath) == 0)
 		return -1;
 
+	
+
 	/* initialize counters */
 	dnsservers = 0;
 	ntpservers = 0;
@@ -106,54 +132,56 @@ client6_script(scriptpath, state, optinf
 	bcmcsnamelen = 0;
 	envc = 2;     /* we at least include the reason and the terminator */
 
-	/* count the number of variables */
-	for (v = TAILQ_FIRST(&optinfo->dns_list); v; v = TAILQ_NEXT(v, link))
-		dnsservers++;
-	envc += dnsservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->dnsname_list); v;
-	    v = TAILQ_NEXT(v, link)) {
-		dnsnamelen += v->val_vbuf.dv_len;
-	}
-	envc += dnsnamelen ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->ntp_list); v; v = TAILQ_NEXT(v, link))
-		ntpservers++;
-	envc += ntpservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->sip_list); v; v = TAILQ_NEXT(v, link))
-		sipservers++;
-	envc += sipservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->sipname_list); v;
-	    v = TAILQ_NEXT(v, link)) {
-		sipnamelen += v->val_vbuf.dv_len;
-	}
-	envc += sipnamelen ? 1 : 0;
+	/* count the number of variables */  
+	if(state != DHCP6S_EXIT)
+	{
+		for (v = TAILQ_FIRST(&optinfo->dns_list); v; v = TAILQ_NEXT(v, link))
+			dnsservers++;
+		envc += dnsservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->dnsname_list); v;
+		    v = TAILQ_NEXT(v, link)) {
+			dnsnamelen += v->val_vbuf.dv_len;
+		}
+		envc += dnsnamelen ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->ntp_list); v; v = TAILQ_NEXT(v, link))
+			ntpservers++;
+		envc += ntpservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->sip_list); v; v = TAILQ_NEXT(v, link))
+			sipservers++;
+		envc += sipservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->sipname_list); v;
+		    v = TAILQ_NEXT(v, link)) {
+			sipnamelen += v->val_vbuf.dv_len;
+		}
+		envc += sipnamelen ? 1 : 0;
 
-	for (v = TAILQ_FIRST(&optinfo->nis_list); v; v = TAILQ_NEXT(v, link))
-		nisservers++;
-	envc += nisservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->nisname_list); v;
-	    v = TAILQ_NEXT(v, link)) {
-		nisnamelen += v->val_vbuf.dv_len;
-	}
-	envc += nisnamelen ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->nis_list); v; v = TAILQ_NEXT(v, link))
+			nisservers++;
+		envc += nisservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->nisname_list); v;
+		    v = TAILQ_NEXT(v, link)) {
+			nisnamelen += v->val_vbuf.dv_len;
+		}
+		envc += nisnamelen ? 1 : 0;
 
-	for (v = TAILQ_FIRST(&optinfo->nisp_list); v; v = TAILQ_NEXT(v, link))
-		nispservers++;
-	envc += nispservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->nispname_list); v;
-	    v = TAILQ_NEXT(v, link)) {
-		nispnamelen += v->val_vbuf.dv_len;
-	}
-	envc += nispnamelen ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->nisp_list); v; v = TAILQ_NEXT(v, link))
+			nispservers++;
+		envc += nispservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->nispname_list); v;
+		    v = TAILQ_NEXT(v, link)) {
+			nispnamelen += v->val_vbuf.dv_len;
+		}
+		envc += nispnamelen ? 1 : 0;
 
-	for (v = TAILQ_FIRST(&optinfo->bcmcs_list); v; v = TAILQ_NEXT(v, link))
-		bcmcsservers++;
-	envc += bcmcsservers ? 1 : 0;
-	for (v = TAILQ_FIRST(&optinfo->bcmcsname_list); v;
-	    v = TAILQ_NEXT(v, link)) {
-		bcmcsnamelen += v->val_vbuf.dv_len;
+		for (v = TAILQ_FIRST(&optinfo->bcmcs_list); v; v = TAILQ_NEXT(v, link))
+			bcmcsservers++;
+		envc += bcmcsservers ? 1 : 0;
+		for (v = TAILQ_FIRST(&optinfo->bcmcsname_list); v;
+		    v = TAILQ_NEXT(v, link)) {
+			bcmcsnamelen += v->val_vbuf.dv_len;
+		}
+		envc += bcmcsnamelen ? 1 : 0;
 	}
-	envc += bcmcsnamelen ? 1 : 0;
-
 	/* allocate an environments array */
 	if ((envp = malloc(sizeof (char *) * envc)) == NULL) {
 		d_printf(LOG_NOTICE, FNAME,
@@ -170,216 +198,219 @@ client6_script(scriptpath, state, optinf
 	if ((envp[i++] = strdup(reason)) == NULL) {
 		d_printf(LOG_NOTICE, FNAME,
 		    "failed to allocate reason strings");
-		ret = -1;
+		ret = -1; 
 		goto clean;
 	}
+
 	/* "var=addr1 addr2 ... addrN" + null char for termination */
-	if (dnsservers) {
-		elen = sizeof (dnsserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * dnsservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for DNS servers");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", dnsserver_str);
-		for (v = TAILQ_FIRST(&optinfo->dns_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+	if(state != DHCP6S_EXIT)
+	{
+		if (dnsservers) {
+			elen = sizeof (dnsserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * dnsservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for DNS servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", dnsserver_str);
+			for (v = TAILQ_FIRST(&optinfo->dns_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
-		}
-	}
-	if (ntpservers) {
-		elen = sizeof (ntpserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * ntpservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for NTP servers");
-			ret = -1;
-			goto clean;
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", ntpserver_str);
-		for (v = TAILQ_FIRST(&optinfo->ntp_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+		if (ntpservers) {
+			elen = sizeof (ntpserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * ntpservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for NTP servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", ntpserver_str);
+			for (v = TAILQ_FIRST(&optinfo->ntp_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-	}
 
-	if (dnsnamelen) {
-		elen = sizeof (dnsname_str) + dnsnamelen + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for DNS name");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", dnsname_str);
-		for (v = TAILQ_FIRST(&optinfo->dnsname_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			strlcat(s, v->val_vbuf.dv_buf, elen);
-			strlcat(s, " ", elen);
+		if (dnsnamelen) {
+			elen = sizeof (dnsname_str) + dnsnamelen + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for DNS name");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", dnsname_str);
+			for (v = TAILQ_FIRST(&optinfo->dnsname_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				strlcat(s, v->val_vbuf.dv_buf, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-	}
 
-	if (sipservers) {
-		elen = sizeof (sipserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * sipservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for SIP servers");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", sipserver_str);
-		for (v = TAILQ_FIRST(&optinfo->sip_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+		if (sipservers) {
+			elen = sizeof (sipserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * sipservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for SIP servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", sipserver_str);
+			for (v = TAILQ_FIRST(&optinfo->sip_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
-		}
-	}
-	if (sipnamelen) {
-		elen = sizeof (sipname_str) + sipnamelen + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for SIP domain name");
-			ret = -1;
-			goto clean;
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", sipname_str);
-		for (v = TAILQ_FIRST(&optinfo->sipname_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			strlcat(s, v->val_vbuf.dv_buf, elen);
-			strlcat(s, " ", elen);
+		if (sipnamelen) {
+			elen = sizeof (sipname_str) + sipnamelen + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for SIP domain name");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", sipname_str);
+			for (v = TAILQ_FIRST(&optinfo->sipname_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				strlcat(s, v->val_vbuf.dv_buf, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-	}
 
-	if (nisservers) {
-		elen = sizeof (nisserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * nisservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for NIS servers");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", nisserver_str);
-		for (v = TAILQ_FIRST(&optinfo->nis_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+		if (nisservers) {
+			elen = sizeof (nisserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * nisservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for NIS servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", nisserver_str);
+			for (v = TAILQ_FIRST(&optinfo->nis_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
-		}
-	}
-	if (nisnamelen) {
-		elen = sizeof (nisname_str) + nisnamelen + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for NIS domain name");
-			ret = -1;
-			goto clean;
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", nisname_str);
-		for (v = TAILQ_FIRST(&optinfo->nisname_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			strlcat(s, v->val_vbuf.dv_buf, elen);
-			strlcat(s, " ", elen);
+		if (nisnamelen) {
+			elen = sizeof (nisname_str) + nisnamelen + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for NIS domain name");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", nisname_str);
+			for (v = TAILQ_FIRST(&optinfo->nisname_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				strlcat(s, v->val_vbuf.dv_buf, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-	}
 
-	if (nispservers) {
-		elen = sizeof (nispserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * nispservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for NIS+ servers");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", nispserver_str);
-		for (v = TAILQ_FIRST(&optinfo->nisp_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+		if (nispservers) {
+			elen = sizeof (nispserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * nispservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for NIS+ servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", nispserver_str);
+			for (v = TAILQ_FIRST(&optinfo->nisp_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
-		}
-	}
-	if (nispnamelen) {
-		elen = sizeof (nispname_str) + nispnamelen + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for NIS+ domain name");
-			ret = -1;
-			goto clean;
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", nispname_str);
-		for (v = TAILQ_FIRST(&optinfo->nispname_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			strlcat(s, v->val_vbuf.dv_buf, elen);
-			strlcat(s, " ", elen);
+		if (nispnamelen) {
+			elen = sizeof (nispname_str) + nispnamelen + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for NIS+ domain name");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", nispname_str);
+			for (v = TAILQ_FIRST(&optinfo->nispname_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				strlcat(s, v->val_vbuf.dv_buf, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-	}
 
-	if (bcmcsservers) {
-		elen = sizeof (bcmcsserver_str) +
-		    (INET6_ADDRSTRLEN + 1) * bcmcsservers + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for BCMC servers");
-			ret = -1;
-			goto clean;
-		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", bcmcsserver_str);
-		for (v = TAILQ_FIRST(&optinfo->bcmcs_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			char *addr;
+		if (bcmcsservers) {
+			elen = sizeof (bcmcsserver_str) +
+			    (INET6_ADDRSTRLEN + 1) * bcmcsservers + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for BCMC servers");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", bcmcsserver_str);
+			for (v = TAILQ_FIRST(&optinfo->bcmcs_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				char *addr;
 
-			addr = in6addr2str(&v->val_addr6, 0);
-			strlcat(s, addr, elen);
-			strlcat(s, " ", elen);
-		}
-	}
-	if (bcmcsnamelen) {
-		elen = sizeof (bcmcsname_str) + bcmcsnamelen + 1;
-		if ((s = envp[i++] = malloc(elen)) == NULL) {
-			d_printf(LOG_NOTICE, FNAME,
-			    "failed to allocate strings for BCMC domain name");
-			ret = -1;
-			goto clean;
+				addr = in6addr2str(&v->val_addr6, 0);
+				strlcat(s, addr, elen);
+				strlcat(s, " ", elen);
+			}
 		}
-		memset(s, 0, elen);
-		snprintf(s, elen, "%s=", bcmcsname_str);
-		for (v = TAILQ_FIRST(&optinfo->bcmcsname_list); v;
-		    v = TAILQ_NEXT(v, link)) {
-			strlcat(s, v->val_vbuf.dv_buf, elen);
-			strlcat(s, " ", elen);
+		if (bcmcsnamelen) {
+			elen = sizeof (bcmcsname_str) + bcmcsnamelen + 1;
+			if ((s = envp[i++] = malloc(elen)) == NULL) {
+				d_printf(LOG_NOTICE, FNAME,
+				    "failed to allocate strings for BCMC domain name");
+				ret = -1;
+				goto clean;
+			}
+			memset(s, 0, elen);
+			snprintf(s, elen, "%s=", bcmcsname_str);
+			for (v = TAILQ_FIRST(&optinfo->bcmcsname_list); v;
+			    v = TAILQ_NEXT(v, link)) {
+				strlcat(s, v->val_vbuf.dv_buf, elen);
+				strlcat(s, " ", elen);
+			}
 		}
 	}
-
 	/* launch the script */
 	pid = fork();
 	if (pid < 0) {
@@ -432,6 +463,5 @@ client6_script(scriptpath, state, optinf
 	for (i = 0; i < envc; i++)
 		free(envp[i]);
 	free(envp);
-
 	return ret;
 }
