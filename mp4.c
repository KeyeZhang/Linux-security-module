#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
//add
#include <linux/xattr.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	/*
	 * Add your code here
	 * ...
	 */
	struct dentry *dentry;
	int size;
	int ret;
	char *cred_ctx;
	int sid;

	//error handling for inode
	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
		return MP4_NO_ACCESS;
	}

	//get dentry of inode
	dentry = d_find_alias(inode);

	//error handling dentry
	if (!dentry) {
		return MP4_NO_ACCESS;
	}

	size = 128;
	cred_ctx = kmalloc(size, GFP_KERNEL);
	if(!cred_ctx) {
		dput(dentry);
		return MP4_NO_ACCESS;
	}

	//first time get xattr and error handling
	ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, cred_ctx, size);
	size = ret;

	if(ret == -ERANGE) {
		//buffer overflows, should query the correct buffer size
		kfree(cred_ctx);
		ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, NULL, 0);
		//queried size even < 0, error, terminate.
		if(ret < 0) {
			dput(dentry);
			return MP4_NO_ACCESS;
		}

		//update the size by the newly queried correct size
		size = ret;
		cred_ctx = kmalloc(size, GFP_KERNEL);
		if(!cred_ctx) {
			dput(dentry);
			return -ENOMEM;
		}
		//second time get xattr and error handling
		ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, cred_ctx, size);
	}

	if(ret < 0) {
		dput(dentry);
		kfree(cred_ctx);
		return MP4_NO_ACCESS;
	} else {
		dput(dentry);
		kfree(cred_ctx);
		cred_ctx[size] = '\0';
		sid = __cred_ctx_to_sid(cred_ctx);
	}

	return sid;

}

/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */

 //This hook is responsible for setting the credentials cred_ctx (and thus our subjective security blob) for each process that is launched from a given binary file.
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{

	//const char * fileName = bprm -> filename;
	if(!bprm || !bprm->file || !bprm->file->f_inode){
		return -ENOMEM;
	}
	struct inode * inode = bprm->file->f_inode;

	//getting dentry: d_find_alias(bprm->file->f_inode)?

	//1.read the xattr value of the inode used to create the process
	//https://piazza.com/class/jcgqvneo9tn1o0?cid=460
	//read the xattr value of the inode, get the label out of it
	int osid = get_inode_sid(inode);

	//2.if that labels reads MP4 TARGET SID
	//you should set the created task’s blob to MP4 TARGET SID as well.
	if (osid == MP4_TARGET_SID) {
		if (!(bprm -> cred)) {
			return -ENOMEM;
		}
		if(!(bprm -> cred -> security)) {
			return -ENOMEM;
		}
		bprm -> cred -> security -> mp4_flags = osid
	}

	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */

 //In Linux, all of a task’s credentials are held in (uid, gid) or through (groups, keys, LSM security) a refcounted structure of type ‘struct cred’. Each task points to its credentials by a pointer called ‘cred’ in its task_struct.

static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	 if(!cred){
		 return -ENOMEM;
	 }
     //Add your code here
	 struct mp4_security * my_security_blob;
	 my_security_blob = kzalloc(sizeof(struct mp4_security), gfp);
	 if(!my_security_blob) {
		 return -ENOMEM;
	 }
	 //initialized label should always be MP4_NO_ACCESS
	 my_security_blob -> mp4_flags = MP4_NO_ACCESS;
	 //hook the void pointer from cred to the new security blob we created
	 cred -> security = my_security_blob;
	 //pr_info("1ST HOOK: mp4_cred_alloc_blank succeeds!");
	 return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	/*
	 * Add your code here
	 * ...
	 */
	 struct mp4_security * curr_blob;

	 if(!cred) {
		 return -ENOMEM;
	 }

	 curr_blob = cred->security;

	 if(!curr_blob) {
		 return -ENOMEM;
	 }
	 /*
	  * cred->security == NULL if security_cred_alloc_blank() or
	  * security_prepare_creds() returned an error.
	  */
	 BUG_ON(cred->security && (unsigned long) cred->security < PAGE_SIZE);
	 cred->security = (void *) 0x7UL;
	 kfree(curr_blob);

	 pr_info("2ND HOOK: mp4_cred_free succeeds!");
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	const struct mp4_security *old_blob;
	struct mp4_security * new_blob;

	if(!new || !old) {
		return -ENOMEM;
	}

	old_blob = old->security;
	if(!old_blob) {
		return -ENOMEM;
	}

	new_blob = (struct mp4_security*)kmalloc(sizeof(struct mp4_security), gfp);
	// new_blob = kmemdup(old_blob, sizeof(struct mp4_security), gfp);
	if (!new_blob)
		return -ENOMEM;

	new_blob -> mp4_flags = old_blob -> mp4_flags;

	new->security = new_blob;

	//pr_info("3RD HOOK: mp4_cred_prepare succeeds!");

	return 0;

}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */

 /*
 	This hook is responsible for setting the xattr of a newly created inode.
    This value will depend on whether the task that creates this inode has the target sid or not:
    1. For those inodes that were created by a target process, they should always be labeled with the read-write attribute.
    2. For all other inodes, you should not set any xattr value.
*/

//https://piazza.com/class/jcgqvneo9tn1o0?cid=418
//https://elixir.bootlin.com/linux/v4.3/source/include/linux/lsm_hooks.h#L168

static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
	if(!current_cred() || !current_cred()->security){
		return -ENOMEM;
	}

	int task_sid = current_cred()->security->mp4_flags; //how to get the current task's security blob: current_cred()?
	char *name_ptr, *value_ptr;

	if(!inode || !dir) {
		return -EOPNOTSUPP;
	}

	// put the attribute name
	// use kmalloc?
	name_ptr = kstrdup(XATTR_MP4_SUFFIX, GFP_KERNEL);
	if(!name_ptr) {
		return -ENOMEM;
	}
	*name = name_ptr;

	// put the value and length
	if(task_sid == MP4_TARGET_SID) {
		//put length
		*len = 7;
		//put value
		valuep = kstrdup("target", GFP_KERNEL);
		//error handling
		if (!valuep) {
			return -ENOMEM;
		}
		*value = valuep;
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}


/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */

static int mp4_has_permission(int ssid, int osid, int mask)
{

	return 0;  /* should not get here */

}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */

 //For those programs that are not labeled as target
 //our module will allow them full access to directories (regardless of the directories’ security labels), //and will allow them read-only access to files that have been assigned one of our custom labels.

static int mp4_inode_permission(struct inode *inode, int mask)
{

	 struct dentry *dentry = (struct dentry *)NULL;
	 char *dir;
	 char *buf;
	 int ret;
	 int len = 128;

	 if (!mask) {
		 return 0;
	 }

	 // Your code MUST first obtain the path of the inode being checked, and then use the helper function to skip over certain paths heavily used during boot time.

	 //get the dir name by using dentry
	 dentry = d_find_alias(inode);
	 if(!dentry) {
		 return -EACCES;
	 }

	 buf = kmalloc(len, GFP_KERNEL);
	 if(!buf) {
		 dput(dentry)
		 return -EACCES;
	 }

     buf = memset(buf, '\0', len);
	 dir = d_path(dentry, buf, len-1);

	 //should skip path
	 if (dir && mp4_should_skip_path(dir)) {
		 dput(dentry);
		 kfree(buf);
	 	 return 0; //TODO: skip is granted or no access?
	 }

	 if (!current_cred()->security ) {  // ssid
		 return NONACCESS;
	 }
	 int ssid = current_cred()->security->mp4_flags;
	 int osid = get_inode_sid(inode);

	 ret = mp4_has_permission(ssid, osid, mask);

	 /* Then, use this code to print relevant denials: for our processes or on our objects */
 	if (( ssid && osid ) && ret ) {
 		pr_info("%s: task ssid: %d, NOT authorized, for inode osid: %d.\n", ssid, osid);
 	}

 	/* Then, use this code to print relevant authorizations: for our processes */
 	if (( ssid && osid ) && !ret) {
 		pr_info("%s: task ssid: %d, Authorized, for inode osid: %d.\n", ssid, osid);
 	}

	 return ret; /* permissive */

}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("Mytest: mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
