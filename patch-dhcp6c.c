--- dhcp6c.c.orig	2016-12-19 08:16:42 UTC
+++ dhcp6c.c
@@ -82,9 +82,12 @@
 
 static int debug = 0;
 static int exit_ok = 0;
+
 static sig_atomic_t sig_flags = 0;
 #define SIGF_TERM 0x1
 #define SIGF_HUP 0x2
+#define SIGF_QUIT 0x4
+
 
 const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_CLIENT;
 
@@ -109,6 +112,7 @@ static int ctldigestlen;
 static int infreq_mode = 0;
 
 int opt_norelease;
+static char *script_p;
 
 static inline int get_val32 __P((char **, int *, u_int32_t *));
 static inline int get_ifname __P((char **, int *, char *, int));
@@ -390,6 +394,11 @@ client6_init()
 		    strerror(errno));
 		exit(1);
 	}
+	if (signal(SIGUSR1, client6_signal) == SIG_ERR) {
+		d_printf(LOG_WARNING, FNAME, "failed to set signal: %s",
+		    strerror(errno));
+		exit(1);
+	}
 }
 
 int
@@ -454,6 +463,9 @@ free_resources(freeifp)
 {
 	struct dhcp6_if *ifp;
 
+	
+	script_p = NULL;
+	
 	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
 		struct dhcp6_event *ev, *ev_next;
 
@@ -461,6 +473,11 @@ free_resources(freeifp)
 			continue;
 
 		/* release all IAs as well as send RELEASE message(s) */
+		if(script_p == NULL) {
+		    script_p = ifp->scriptpath;
+		    
+		}
+		
 		release_all_ia(ifp);
 
 		/*
@@ -483,31 +500,45 @@ check_exit()
 {
 	struct dhcp6_if *ifp;
 
+	
+	
 	if (!exit_ok)
 		return;
 
-	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
-		/*
-		 * Check if we have an outstanding event.  If we do, we cannot
-		 * exit for now.
-		 */
-		if (!TAILQ_EMPTY(&ifp->event_list))
+	if(exit_ok) {
+	  
+		for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
+			/*
+			* Check if we have an outstanding event.  If we do, we cannot
+			* exit for now.
+			*/
+			
+			if (!TAILQ_EMPTY(&ifp->event_list))
 			return;
+		}
 	}
-
+	
 	/* We have no existing event.  Do exit. */
 	d_printf(LOG_INFO, FNAME, "exiting");
-
+	
+	if (strlen(script_p) != 0) {
+		 
+	       /* We are going to fire the script with and exit value */
+	        d_printf(LOG_DEBUG, FNAME, "shutdown executes %s", script_p);
+		client6_script(script_p, DHCP6S_EXIT, NULL);
+	} 
+	unlink(pid_file);
 	exit(0);
 }
 
 static void
 process_signals()
 {
+     
+	 
 	if ((sig_flags & SIGF_TERM)) {
 		exit_ok = 1;
 		free_resources(NULL);
-		unlink(pid_file);
 		check_exit();
 	}
 	if ((sig_flags & SIGF_HUP)) {
@@ -515,6 +546,13 @@ process_signals()
 		free_resources(NULL);
 		client6_startall(1);
 	}
+	if ((sig_flags & SIGF_QUIT)) {
+		d_printf(LOG_DEBUG, FNAME, "Forcing Exit");
+		exit_ok = 1;
+		opt_norelease = 1;
+		free_resources(NULL);
+		check_exit();
+	}
 
 	sig_flags = 0;
 }
@@ -1161,6 +1199,9 @@ client6_signal(sig)
 	case SIGHUP:
 		sig_flags |= SIGF_HUP;
 		break;
+	case SIGUSR1:
+		sig_flags |= SIGF_QUIT;
+		break;
 	}
 }
 
@@ -1751,23 +1792,23 @@ client6_recvreply(ifp, dh6, len, optinfo
 
 	switch (state) {
 	case DHCP6S_INFOREQ:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received INFOREQ");
-		break;  
-	case DHCP6S_REQUEST:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received REQUEST");
-		break;
-	case DHCP6S_RENEW:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received INFO");
-		break;
-	case DHCP6S_REBIND:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received REBIND");
-		break;
-	case DHCP6S_RELEASE:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received RELEASE");
-		break;
-	case DHCP6S_SOLICIT:
-		d_printf(LOG_INFO, FNAME, "dhcp6c Received SOLICIT");
-		break;          
+		d_printf(LOG_INFO, FNAME, "Received Info");
+ 		break;  
+ 	case DHCP6S_REQUEST:
+		d_printf(LOG_INFO, FNAME, "Received Reply");
+ 		break;
+ 	case DHCP6S_RENEW:
+		d_printf(LOG_INFO, FNAME, "Received Renew");
+ 		break;
+ 	case DHCP6S_REBIND:
+		d_printf(LOG_INFO, FNAME, "Received Rebind");
+ 		break;
+ 	case DHCP6S_RELEASE:
+		d_printf(LOG_INFO, FNAME, "Received Release");
+ 		break;
+ 	case DHCP6S_SOLICIT:
+		d_printf(LOG_INFO, FNAME, "Received Advert");
+ 		break;             
 	}
 
 	/* A Reply message must contain a Server ID option */
