/*
 * mod_suid.c for Apache 1.3.xx
 *
 * Copyright 2002 by Igmar Palsenberg. Original idea by Anthony Howe.
 * Copyright 2006 by Igmar Palsenberg
 *
 * See the LICENSE file for details about licensing 
 *
 *
 * W A R N I N G
 * -------------
 *
 * USE OF THIS MODULE MAY OPEN SECURITY EXPLOITS WITHIN APACHE AND ITS
 * INSTALLED MODULES. THE AUTHOR DOES NOT RECOMMEND THE USE OF THIS MODULE.
 * THE AUTHOR DOES NOT ACCEPT ANY RESPONSIBLITY FOR SECURITY BREACHES ON
 * ANY WEB SERVER WHERE THIS MODULE IS EMPLOYED, NOR ANY SECURITY BREACHES
 * ON THOSE COMPUTERS ACCESSIBLE FROM A WEB SERVER EMPLOYING THIS MODULE.
 * USE AT YOUR OWN RISK.
 *
 * SECURITY ISSUES
 * ---------------
 *
 *  1.	Apache 1.3.xx must be compiled with -DBIG_SECURITY_HOLE in order for
 *	this module to work when NOT using the lsm_suid kernel module
 *
 *  2.	"User root" directive must be set so that the child processes using
 *	this module can perform a setuid() and setgid(). If the User
 *	directive is set to someone else then this module is disabled.
 *
 *	When using the lsm_suid kernel module, the above does not apply.
 *
 *  3.	Nothing is done about open file descriptors and therefore they could
 *	be subverted in some manner, such as to corrupt web server logs.
 *
 *  4.	Apache processes handlers in reverse order from which they were
 *	loaded. Its highly recommended that mod_suid be the last module in
 *	the LoadModule sequence, because in this way mod_suid's handler
 *	will be the first executed within its applied phase, so no other
 *	module can skip mod_suid.
 *
 *  6.	mod_suid is applied in phase 4, host acccess control, because this
 *	phase loosely corresponds with mod_suid's purpose, application of
 *	user/group file access control.
 *
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"

#include "config.h"

#ifndef HAVE_SETRESUID
# error You need SETRESUID
#endif

#ifndef HAVE_SETRESGID
# error You need SETRESGID
#endif

/* {{{ defines */
#define MODULE			"mod_suid"
#define AUTHOR			"Igmar Palsenberg <igmar@palsenberg.com>"
#define VERSION			"2.0"
#define UID_MIN			50
#define GID_MIN			50
#define RSUID_FMT_ENABLE	"/proc/%d/attr/exec"
#define RSUID_FMT_CHECK		"/proc/%d/attr/current"
#define RSUID_CMD_ENABLE	"rsuid enable"
#define RSUID_ENABLE_FILE	"/proc/sys/kernel/rsuid/enabled"

#define MODSUID_DISABLED	0
#define MODSUID_CLASSIC		1
#define MODSUID_RSUID		2

#define MODSUID_APACHE_USER	-2
#define MODSUID_APACHE_GROUP	-2
#define MODSUID_ROOT_USER	-3
#define MODSUID_ROOT_GROUP	-3


#define POLICY_OFF		0
#define POLICY_FILE		1
#define POLICY_USER_GROUP	2
#define POLICY_DOCUMENT_ROOT	3
#define POLICY_PARENT_DIRECTORY	4

#ifndef TRUE
# define TRUE			1
#endif

#ifndef FALSE
# define FALSE			0
#endif

/* Inline related stuff */
#ifdef INLINE 
# define MSINLINE inline
#else
# define MSINLINE
#endif

#define UNSET			-1
#define MERGE(p, c)		(c == UNSET ? p : c)
/* }}} */

/* {{{ define suid_module */
module MODULE_VAR_EXPORT suid_module;
/* }}} */

/* {{{ suid_srv_config */
typedef struct suid_srv_config {
	int global_enabled;	/* 1 when globally enabled */
	int enabled;		/* Actually a tri value */
	int rsuid;		/* Can we enable rsuid restrictions ? */
	int sig_enabled;	/* Enabled / disable signature */
	int policy;		/* Suid policy */
	uid_t apache_uid;	/* The apache idle uid */
	gid_t apache_gid;	/* The apache idle gid */
	uid_t target_uid;	/* Suid target uid */
	gid_t target_gid;	/* Suid target gid */
} suid_srv_config;
/* }}} */

/* {{{ static prototypes */
static int istrue(char *s);
static void * create_server_entry(pool *p, server_rec *s);
static void init_module(server_rec *s, pool *p);
static void * merge_server_entries(pool *p, void * s_parent, void * s_current);
static void child_init(server_rec *s, pool *p);
static int uri_handler(request_rec * r);
static int access_handler(request_rec *r);
static int fixup_handler(request_rec *r);
static int rsuid_active(void);
static int rsuid_enable_restrictions(void);
static int change_user(suid_srv_config *sconf, request_rec *r, uid_t uid, gid_t gid);
/* }}} */

/* {{{ static prototypes config */
static const char * mod_suid_enable(cmd_parms *cmd, void *dconfig, int flag);
static const char * mod_suid_sig(cmd_parms *cmd, void *dconfig, int flag);
static const char * mod_suid_apache_user(cmd_parms *cmd, void *dconfig, char *p1);
static const char * mod_suid_apache_group(cmd_parms *cmd, void *dconfig, char *p1);
static const char * suid_user_group(cmd_parms *cmd, void *dconfig, char *p1, char *p2);
static const char * suid_policy(cmd_parms *cmd, void *dconfig, char *p1);
static const char * suid_enable(cmd_parms *cmd, void *dconfig, int flag);
/* }}} */

/* {{{ static int istrue */
static int istrue(char *s)
{
	if (ap_strcasecmp_match(s, "enable") == 0)	/* disable */
		return TRUE;
	if (ap_strcasecmp_match(s, "true") == 0)	/* false */
		return TRUE;
	if (ap_strcasecmp_match(s, "yes") == 0)		/* no */
		return TRUE;
	if (ap_strcasecmp_match(s, "set") == 0)		/* reset */
		return TRUE;
	if (ap_strcasecmp_match(s, "ok") == 0)		/* bogus */
		return TRUE;
	if (ap_strcasecmp_match(s, "on") == 0)		/* off */
		return TRUE;
	if (ap_strcasecmp_match(s, "1") == 0)		/* 0 */
		return TRUE;

	return FALSE;
}
/* }}} */

/* {{{ static void * create_server_entry(pool *p, server_rec *s) */
static void * create_server_entry(pool *p, server_rec *s)
{
	suid_srv_config *config = (suid_srv_config *) ap_pcalloc(p, sizeof(suid_srv_config));

	/* This options are always false and must be explicitly set true. */
	config->global_enabled = FALSE;
	config->enabled = UNSET;
	config->rsuid = UNSET;
	config->sig_enabled = UNSET;
	
	/* These values can be inherited from the parent server. */
	config->apache_uid = UNSET;
	config->apache_gid = UNSET;
	config->target_uid = UNSET;
	config->target_gid = UNSET;
	config->policy = UNSET;

	return (void *) config;
}
/* }}} */

/* {{{ static void init_module(server_rec *s, pool *p) */
static void init_module(server_rec *s, pool *p)
{
	suid_srv_config *sconf;

	sconf = (suid_srv_config *) ap_get_module_config(
		s->module_config, &suid_module
	);

	if (sconf->sig_enabled == TRUE)
		ap_add_version_component("mod_suid/"VERSION);

	if (sconf->enabled != FALSE) {
		return;
	}

	switch (sconf->rsuid) {
		case MODSUID_RSUID:
			break;
		case MODSUID_CLASSIC:
		default:
			if (s->server_uid != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, s, "mod_suid: User root isn't set in the config, and you're not using lsm_rsuid");
				exit(1);
			}
			break;
	}
}
/* }}} */

/* {{{ static void * merge_server_entries(pool *p, void * s_parent, void * s_current) */
static void * merge_server_entries(pool *p, void * s_parent, void * s_current)
{
	suid_srv_config *parent = (suid_srv_config *) s_parent;
	suid_srv_config *current = (suid_srv_config *) s_current;
	suid_srv_config *merged;

	if (current == NULL)
		return parent;
	if (parent == NULL)
		return current;

	merged = (suid_srv_config *) ap_pcalloc(p, sizeof (suid_srv_config));

	if (parent->global_enabled == FALSE)
		merged->enabled = FALSE;
	else
		merged->enabled = MERGE(parent->enabled, current->enabled);

	/* Take parent values, can't be changed per vhost */
	merged->rsuid = MERGE(parent->rsuid, parent->rsuid);
	merged->sig_enabled = MERGE(parent->sig_enabled, current->sig_enabled);
	merged->apache_uid = MERGE(parent->apache_uid, current->apache_uid);
	merged->apache_gid = MERGE(parent->apache_gid, current->apache_gid);
	merged->target_uid = MERGE(parent->target_uid, current->target_uid);
	merged->target_gid = MERGE(parent->target_gid, current->target_gid);
	merged->policy = MERGE(parent->policy, current->policy);

	return (void *) merged;
}
/* }}} */

/* {{{ static void child_init(server_rec *s, pool *p) */
static void child_init(server_rec *s, pool *p)
{
	suid_srv_config *sconf;

	sconf = (suid_srv_config *) ap_get_module_config(
		s->module_config, &suid_module
	);

	change_user(sconf, NULL, MODSUID_APACHE_USER, MODSUID_APACHE_GROUP);
}
/* }}} */

/* ********************************* Global parameters ********************* */
/*
 * ModSuidEnable {boolean}
 * Enabled / disable ModSuid
*/
/* {{{ Config::ModSuidEnable */
static const char * mod_suid_enable(cmd_parms *cmd, void *dconfig, int flag)
{
	suid_srv_config *sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	/* Ok.. Don't allow this in vhosts */
	if (cmd->server->is_virtual) {
		return "ModSuidEnable not allowed in VirtualHost";
	}

	/* 
	 * This can be resolved by moving things around. We choose not to,
	 * the admin should know what he / she is doing
	*/
	if (sconf->apache_uid == UNSET || sconf->apache_gid == UNSET) {
		return "ModSuidEnable should be the last global directive";
	}

	/*
	 * Bah.. Configuration directives are parsed *before* init_module()
	 * is called
	*/
	/* Ignore when set to On and the module is already active */
	if (flag && sconf->global_enabled == TRUE)
		return NULL;

	if (flag) {
		sconf->rsuid = rsuid_active();

		switch (sconf->rsuid) {
			case MODSUID_RSUID:
				if (rsuid_enable_restrictions() == FALSE)
					return "Can't enable rsuid";
				break;
			default:
				break;
		}
	}
	sconf->global_enabled = flag;

	return NULL;
}
/* }}} */

/*
 * SuidSignature {boolean}
 * Enabled / disable ModSuid signature
*/
/* {{{ Config::SuidSignature */
static const char * mod_suid_sig(cmd_parms *cmd, void *dconfig, int flag)
{
	suid_srv_config *sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	/* Ok.. Don't allow this in vhosts */
	if (cmd->server->is_virtual) {
		return "ModSuidSignature not allowed in VirtualHost";
	}

	/* Can we enabled rsuid ? */
	sconf->sig_enabled = flag;
	
	return NULL;
}
/* }}} */

/*
 * ModSuidApacheUser {id}
 * The idle Apache user
*/
/* {{{ Config::ModSuidApacheUser */
static const char * mod_suid_apache_user(cmd_parms *cmd, void *dconfig, char *p1)
{
	struct passwd *pwd = NULL;
	suid_srv_config *sconf = NULL;

	sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	/* Ok.. Don't allow this in vhosts */
	if (cmd->server->is_virtual) {
		return "ModSuidApacheGroup not allowed in VirtualHost";
	}
	
	pwd = getpwnam(p1);
	if (pwd == NULL) {
		return "Can't find uid for user in ModSuidApacheGroup directive";
	}

	if (pwd->pw_uid == 0) {
		return "ModSuidApacheGroup user can't be set to root";
	}

	sconf->apache_uid = pwd->pw_uid;
	
	return NULL;
}
/* }}} */

/*
 * ModSuidApacheGroup {id}
 * The idle Apache Group
*/
/* {{{ Config::ModSuidApacheGroup */
static const char * mod_suid_apache_group(cmd_parms *cmd, void *dconfig, char *p1)
{
	struct group *grp = NULL;
	suid_srv_config *sconf = NULL;

	sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	/* Ok.. Don't allow this in vhosts */
	if (cmd->server->is_virtual) {
		return "ModSuidApacheGroup not allowed in VirtualHost";
	}
	
	grp = getgrnam(p1);
	if (grp == NULL) {
		return "Can't find gid for group in ModSuidApacheGroup directive";
	}

	if (grp->gr_gid == 0) {
		return "ModSuidApacheGroup group can't be set to root";
	}

	sconf->apache_gid = grp->gr_gid;
	
	return NULL;
}
/* }}} */

/* ******************************** VirtualHost parameters ***************** */

/*
 * Suid user {id}
 * Suid group {id}
 *
 * Context: virtual host
 */
/* {{{ Config::Suid */
static const char * suid_user_group(cmd_parms *cmd, void *dconfig, char *p1, char *p2)
{
	suid_srv_config *sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	if (sconf == NULL)
		return NULL;

	if (ap_strcasecmp_match(p1, "user") == 0) {
		sconf->target_uid = ap_uname2id(p2);
	} else if (ap_strcasecmp_match(p1, "group") == 0) {
		sconf->target_gid = ap_gname2id(p2);
	} else {
		return "Invalid argument.";
	}

	return NULL;
}
/* }}} */

/*
 * SuidPolicy {policy}
 *
 * where policy is one of:
 *
 *	file, user-group, document-root, parent-directory
 *
 * Context: server, virtual host, <directory>, <location>
 */
/* {{{ Config::SuidPolicy */
static const char * suid_policy(cmd_parms *cmd, void *dconfig, char *p1)
{
	suid_srv_config *sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	if (sconf == NULL)
		return NULL;

	if (ap_strcasecmp_match(p1, "file") == 0) {
		sconf->policy = POLICY_FILE;
	} else if (ap_strcasecmp_match(p1, "user*group") == 0) {
		sconf->policy = POLICY_USER_GROUP;
	} else if (ap_strcasecmp_match(p1, "doc*root") == 0) {
		sconf->policy = POLICY_DOCUMENT_ROOT;
	} else if (ap_strcasecmp_match(p1, "parent*dir*") == 0) {
		sconf->policy = POLICY_PARENT_DIRECTORY;
	} else {
		return "Invalid policy.";
	}

	return NULL;
}
/* }}} */

/*
 * SuidEnable {boolean}
 *
 * Context: server, virtual host, <directory>, <location>
*/
/* {{{ Config::SuidEnable */
static const char * suid_enable(cmd_parms *cmd, void *dconfig, int flag)
{
	suid_srv_config *sconf = (suid_srv_config *)ap_get_module_config(cmd->server->module_config, &suid_module);

	sconf->enabled = flag;

	return NULL;
}
/* }}} */

/* ******************************* Apache hooks **************************** */
/* {{{ static int uri_handler(request_rec * r) */
static int uri_handler(request_rec * r)
{
	suid_srv_config *sconf;

	sconf = (suid_srv_config *) ap_get_module_config(
		r->server->module_config, &suid_module
	);

	if (sconf->enabled != TRUE)
		return DECLINED;

	/* 
	 * Change to apache user when not enabled, change to root otherwise
	 * since we need the privileges later on
	*/
	if (sconf->enabled == TRUE)
		change_user(sconf, r, MODSUID_ROOT_USER, MODSUID_ROOT_GROUP); 
	else
		change_user(sconf, r, MODSUID_APACHE_USER, MODSUID_APACHE_GROUP);

	return DECLINED;
}
/* }}} */

/* {{{  static int access_handler(request_rec *r) */
static int access_handler(request_rec *r)
{
	uid_t this_uid;
	gid_t this_gid;
	struct stat linfo;
	struct passwd *pw;
	const char *dir = (const char *) 0;
	suid_srv_config *sconf;

	sconf = (suid_srv_config *) ap_get_module_config(
		r->server->module_config, &suid_module
	);

	if (sconf->enabled != TRUE)
		return DECLINED;

#ifndef IGNORE_SYMLINK_OWNER
	/* Precaution: make sure that the owner of a symbolic link is the
	 * same as that of the file the link references. Call me paranoid.
	 * I could have tested further down just before the setgid(), but
	 * I figured it has to get done may as well be sooner than later.
	 */
	if (lstat(r->filename, &linfo) == 0 && S_ISLNK(linfo.st_mode)) {
		if (r->finfo.st_uid != linfo.st_uid) {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "Symbolic link \"%s\" to target file not owned by same user.", r->filename);
			return HTTP_PRECONDITION_FAILED;
		}

		if (r->finfo.st_gid != linfo.st_gid) {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "Symbolic link \"%s\" to target file not owned by same group.", r->filename);
			return HTTP_PRECONDITION_FAILED;
		}
	}
#endif

	switch (sconf->policy) {
		default:
		case POLICY_USER_GROUP:
			/* Use the user & group specified by Suid directive. */
			this_uid = sconf->target_uid;
			this_gid = sconf->target_gid;
			break;
		case POLICY_FILE:
			/* Use the user & group of the requested file. */
			this_uid = r->finfo.st_uid;
			this_gid = r->finfo.st_gid;
			break;
		case POLICY_DOCUMENT_ROOT:
			/* Use the user & group of the site's document root. */
			if (r->uri[0] == '/' && r->uri[1] == '~' && isalnum(r->uri[2])) {
				/* Make sub-request here to find out user's private
				 * document root for their web site, which could have
				 * a different group id from their account profile
				 * and/or home directory.
				 */
				int status;
				request_rec *sub;
				const char *user;
				const char *remainder = r->uri + 2;
	
				user = ap_getword(r->pool, &remainder, '/');
				user = ap_pstrcat(r->pool, "/~", user, "/", NULL);
	
				sub = ap_sub_req_lookup_uri(user, r);
	
				dir = ap_pstrdup(r->pool, sub->filename);
				this_uid = sub->finfo.st_uid;
				this_gid = sub->finfo.st_gid;
				status = sub->status;
	
				ap_destroy_sub_req(sub);
	
				/* When the subrequest to find the ~user's document
				 * root fails, it might be that the user or their
				 * document root has been removed.  We could fall
				 * back on the default user & group, but I think
				 * an error is better.
				 *
				 * NOTE that the 300 class of errors concerning moves
				 * and redirects could be handled differently.
				 */
				if (!ap_is_HTTP_SUCCESS(status)) {
					ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "%s %s: Cannot find \"~%s\" document root", ap_get_server_name(r), r->the_request, user);
					return HTTP_FORBIDDEN;
				}
			} else {
				dir = ap_document_root(r);
			}
			break;
		case POLICY_PARENT_DIRECTORY:
			/* Use the user & group of the immediate parent directory of
			 * our request. If the request refers to a directory, then
			 * the user & group of the directory itself is used.
			 */
			if (S_ISDIR(r->finfo.st_mode)) {
				/* Directory request considered as its own parent. */
				this_uid = r->finfo.st_uid;
				this_gid = r->finfo.st_gid;
			} else {
				/* Parent directory of our request. */
				dir = ap_make_dirstr_parent(r->pool, r->filename);
			}
			break;
	}
	
	if (dir != NULL) {
		struct stat dinfo;

		/* We're still user root at this point, so if we can't
		 * stat() a directory, most likely it doesn't exist,
		 * since we have sufficent permissions to look at it.
		 */
		if (stat(dir, &dinfo) != 0) {
			ap_log_rerror( APLOG_MARK, APLOG_ERR, r, "%s %s: Cannot stat(%s)", ap_get_server_name(r), r->the_request, dir);
			return HTTP_FORBIDDEN;
		}

		this_uid = dinfo.st_uid;
		this_gid = dinfo.st_gid;
	}

	ap_log_rerror( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, "%s %s (%ld): policy=%d, target uid=%ld, gid=%ld, file=%s",
		ap_get_server_name(r), r->the_request, (long) getpid(),
		sconf->policy, (long) this_uid, (long) this_gid,
		r->filename
	);

	if (this_uid == UNSET) {
		ap_log_rerror(
			APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"%s %s: No user ID set",
			ap_get_server_name(r), r->the_request
		);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	if (this_gid == UNSET) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "%s %s: No group ID set", ap_get_server_name(r), r->the_request);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	/* Failure to getpwuid() could mean /etc/passwd has changed while
	 * we are processing this request.  The error is logged, instead
	 * of attempting to fallback on the default Become user.
	 */
	if ((pw = getpwuid(this_uid)) == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: Cannot getpwuid(%ld)", ap_get_server_name(r), r->the_request, (long) this_uid);
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Failure of initgroups() and setgroups() could mean /etc/passwd
	 * and/or /etc/group has changed while we are processing this request.
	 * The error is logged, instead of attempting to fallback on the
	 * default Become user & group.
	 */
	if (initgroups(pw->pw_name, this_gid) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: initgroups(\"%s\", %ld)", ap_get_server_name(r), r->the_request, pw->pw_name, (long) this_gid);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	/* We don't want a switch to UID or GID below a certain treshold */
	if (this_uid <= UID_MIN) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: UID %ld, must be above %ld",
		ap_get_server_name(r), r->the_request, (long) this_uid, (long) UID_MIN);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (this_gid <= GID_MIN) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: GID %ld, must be above %ld", ap_get_server_name(r), r->the_request, (long) this_gid, (long) GID_MIN);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	change_user(sconf, r, this_uid, this_gid);

	/* Success, continue remainder of handler chain. */
	return DECLINED;
}
/* }}} */

/* {{{ static int fixup_handler(request_rec *r) */
static int fixup_handler(request_rec *r)
{
	suid_srv_config *sconf;

	sconf = (suid_srv_config *) ap_get_module_config(
		r->server->module_config, &suid_module
	);

	if (sconf->enabled != TRUE)
		return DECLINED;

	change_user(sconf, r, MODSUID_APACHE_USER, MODSUID_APACHE_GROUP);

	return DECLINED;
}
/* }}} */

/*
 * Function to handle mod_lsm specific stuff
*/
/* {{{ static int rsuid_active(void) */
static int rsuid_active(void)
{
	return access(RSUID_ENABLE_FILE, R_OK | W_OK) == 0 ? MODSUID_RSUID : MODSUID_CLASSIC;
}
/* }}} */

/* {{{ static int rsuid_enable_restrictions(void) */
static int rsuid_enable_restrictions(void)
{
	char buffer[512];
	int fd;
	size_t size;
	pid_t pid;

	pid = getpid();

	/* Bah. Childs also call this, handle it */
	snprintf(buffer, sizeof(buffer), RSUID_FMT_CHECK, pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return FALSE;
	if (read(fd, buffer, sizeof(buffer)) == -1) {
		close(fd);
		return FALSE;
	}
	if (strstr(buffer, "enabled") != NULL) {
		close(fd);
		return TRUE;
	}

	snprintf(buffer, sizeof(buffer), RSUID_FMT_ENABLE, pid);
	fd = open(buffer, O_WRONLY);
	if (fd == -1)
		return FALSE;
	/* write 'rsuid enable' */
	strncpy(buffer, RSUID_CMD_ENABLE, sizeof(buffer));
	size = strlen(buffer);
	if (write(fd, buffer, size) != size) {
		close(fd);
		return FALSE;
	}
	close(fd);

	/* No errors, good. Perform an extra check */
	snprintf(buffer, sizeof(buffer), RSUID_FMT_ENABLE, pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return FALSE;
	if (read(fd, buffer, 10) == -1) {
		if (errno == EINVAL) {
			close(fd);
			return TRUE;
		}
	}
	close(fd);

	return FALSE;
}
/* }}} */

/* {{{ static int change_user(suid_srv_config *sconf, request_rec *r, uid_t uid, gid_t gid) */
static int change_user(suid_srv_config *sconf, request_rec *r, uid_t uid, gid_t gid)
{
	uid_t uid_target = uid;
	uid_t suid_target = uid;
	gid_t gid_target = gid;

	/* Ok.. Do the actual work */
	if (!sconf->enabled == TRUE)
		return TRUE;

	if (uid == MODSUID_APACHE_USER)
		uid_target = sconf->apache_uid;
	if (gid == MODSUID_APACHE_GROUP)
		gid_target = sconf->apache_gid;

	switch (sconf->rsuid) {
		case MODSUID_CLASSIC:
			/* Switch to root first */
			suid_target = -1;
			if (setresuid(0,0,-1) == -1) {
				if (r)
					ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: setresuid(0, 0, -1) failed : %.80s", ap_get_server_name(r), r->the_request, strerror(errno));
				return FALSE;
			}
		/* FALLTHROUGH */
		case MODSUID_RSUID:
			if (uid == MODSUID_ROOT_USER)
				return TRUE;
			/* Set the groups */
			if (setresgid(gid_target, gid_target, gid_target) == -1) {
				if (r)
					ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: setresgid(%d, %d, %d) failed : %.80s", ap_get_server_name(r), r->the_request, gid_target, gid_target, gid_target, strerror(errno));
				return FALSE;
			}
			if (setresuid(uid_target, uid_target, suid_target) == -1) {
				if (r)
					ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s %s: setresuid(%d, %d, %d) failed : %.80s", ap_get_server_name(r), r->the_request, uid_target, uid_target, suid_target, strerror(errno));
				return FALSE;
			}
	}

	return TRUE;
}
/* }}} */

/* {{{ command_table[] */
command_rec command_table[] = {
	{ "ModSuidEnable", mod_suid_enable, NULL, RSRC_CONF, FLAG,
	  "ModSuidEnable {boolean}\nGlobal parameter which enables / disables ModSuid" },
	{ "ModSuidSignature", mod_suid_sig, NULL, RSRC_CONF, FLAG,
	  "ModSuidSignature {boolean}\nGlobal parameter which enables / disables the signature addition" },
	{ "ModSuidApacheUser", mod_suid_apache_user, NULL, RSRC_CONF, TAKE1,
	  "ModSuidApacheUser {id}\nThe idle user when User root is in the httpd.conf" },
	{ "ModSuidApacheGroup", mod_suid_apache_group, NULL, RSRC_CONF, TAKE1,
	  "ModSuidApacheGroup {id}\nThe idle group when Group root is in the httpd.conf" },
	{ "Suid", suid_user_group, NULL, RSRC_CONF, TAKE2,
	  "Suid user {id}\nSuid group {id}\n" },

	{ "SuidPolicy", suid_policy, NULL, RSRC_CONF, TAKE1,
	  "SuidPolicy {policy}\n where policy is one of:\n"
	  "\tfile, user-group, document-root, parent-directory\n" },

	{ "SuidEnable", suid_enable, NULL, RSRC_CONF, FLAG,
	  "SuidEnable {boolean}\nAllow the virtual host to be root user or group.\n" },

	{ NULL }
};
/* }}} */

/* {{{ module suid_module */
module MODULE_VAR_EXPORT suid_module = {
	STANDARD_MODULE_STUFF,
	init_module,			/* module initializer */
	NULL,				/* create per-dir config structures */
	NULL,				/* merge  per-dir config structures */
	create_server_entry,		/* create per-server config */
	merge_server_entries,		/* merge per-server config */
	command_table,			/* table of config file commands */
	NULL,				/* [#8] MIME-typed-dispatched */
	uri_handler,			/* [#1] URI to filename translation */
	NULL,				/* [#4] validate user id from request */
	NULL,				/* [#5] check if the user is ok here */
	access_handler,			/* [#3] check access by host address */
	NULL,				/* [#6] determine MIME type */
	NULL,				/* [#7] pre-run fixups */
	fixup_handler,			/* [#9] log a transaction */
	NULL,				/* [#2] header parser */
	child_init,			/* child_init */
	NULL,				/* child_exit */
	NULL				/* [#0] post read-request */
};
/* }}} */
