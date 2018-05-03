//ali akbar
//UFID 8498-3349
/*
* Sample LSM implementation
*/

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>     /* for sysctl_local_port_range[] */
#include <net/tcp.h>        /* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
//#include <asm/semaphore.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>    /* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>       /* for Unix socket types */
#include <net/af_unix.h>    /* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>

struct task_security_struct {
    u32 sid;
};


MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "sample"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

#define PATHLEN 128

#define SAMPLE_IGNORE 0
#define SAMPLE_UNTRUSTED 1
#define SAMPLE_TRUSTED 2
#define SAMPLE_TARGET_SID 7

/* Mask definitions */
#define MAY_EXEC 1
#define MAY_READ 4
#define MAY_APPEND 8
#define MAY_WRITE 2
#define MAY_WRITE_EXEC 3

/* Mask definitions */
#define NOT_EXEC -1
#define NOT_READ -4
#define NOT_APPEND -8
#define NOT_WRITE -2
#define NOT_WRITE_EXEC -3


extern struct security_operations *security_ops;
/*
* Minimal support for a secondary security module,
* just to allow the use of the capability module.
*/
//static struct security_operations *secondry_ops;


/* Convert context string to sid value (SAMPLE_*) */

static int security_context_to_sid(char *context, u32 *sid)
{
#if 0
    printk(KERN_WARNING "%s: have context: %s\n",
           __FUNCTION__, context);
#endif

    if (!context) return -1;

    if (strcmp(context, "untrusted") == 0) {
        *sid = SAMPLE_UNTRUSTED;
#if 0
        printk(KERN_WARNING "%s: have UN-Trusted context: %s\n",
               __FUNCTION__, context);
#endif
    }
    else if (strcmp(context, "trusted") == 0) {
        *sid = SAMPLE_TRUSTED;
#if 0
        printk(KERN_WARNING "%s: have Trusted context: %s\n",
               __FUNCTION__, context);
#endif
    }
    else if (strcmp(context, "target") == 0)
        *sid = SAMPLE_TARGET_SID;
    else
        *sid = SAMPLE_IGNORE;

#if 0
    printk(KERN_WARNING "%s: have sid: 0x%x\n",
           __FUNCTION__, *sid);
#endif

    return 0;
}


static int has_perm(u32 ssid, u32 osid, u32 ops)
{
#if 1
    if (ssid && osid)
        printk(KERN_WARNING "%s: 0x%x:0x%x:0x%x\n",
               __FUNCTION__, ssid, osid, ops);
#endif
        /* YOUR CODE: LOMAC Authorization Rules */
    /*in this function i try to implement lomac principles which i could understand from the fraser paper
    i am trying to level 1 objects to write or append upper level 2 objects and
    no level 2 object to read and lower level 1 objects
    */
    if( ssid && osid ){
        if( ssid == SAMPLE_IGNORE )
            return 0;
        if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_EXEC)) )
                return NOT_EXEC;
        if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_READ)) )
                return NOT_READ;
        if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_WRITE_EXEC)) )
                return NOT_WRITE_EXEC;
        if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE)) )
                return NOT_WRITE;
        if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_APPEND)) )
                return NOT_APPEND;
        if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE_EXEC)) )
                return NOT_WRITE_EXEC;
        return 0;
    }
        /* Other processes - allow */
        else return 0;

    return -9;  /* should not get here */
}


static u32 inode_init_with_dentry(struct dentry *dentry, struct inode *inode)
{
    int len, rc;
    char *context;
    u32 sid;

    if (!inode->i_op->getxattr) {
        goto out;
    }

/* Need a dentry, since the xattr API requires one.
   Life would be simpler if we could just pass the inode. */

    if (!dentry) {
        printk(KERN_WARNING "%s:  no dentry for dev=%s "
               "ino=%ld\n", __FUNCTION__, inode->i_sb->s_id,
               inode->i_ino);
        goto out;
    }

    len = INITCONTEXTLEN;
    context = kmalloc(len, GFP_KERNEL);
    if (!context) {
        dput(dentry);
        printk(KERN_WARNING "%s: kmalloc error exit\n",
               __FUNCTION__);
        goto out;
    }
    rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
                   context, len);
    len = rc;
    if (rc == -ERANGE) {
        /* Need a larger buffer.  Query for the right size. */
        rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
                       NULL, 0);
        if (rc < 0) {
            dput(dentry);
            kfree(context);
            goto out;
        }
        kfree(context);
        len = rc;
        context = kmalloc(len, GFP_KERNEL);
        if (!context) {
            rc = -ENOMEM;
            dput(dentry);
            printk(KERN_WARNING "%s: no mem error exit\n",
                   __FUNCTION__);
            goto out;
        }
        rc = inode->i_op->getxattr(dentry,
                       XATTR_NAME_SAMPLE,
                       context, len);
    }
    dput(dentry);
    if (rc < 0) {
        kfree(context);
        goto out;
    } else {
        /* not always null terminated at length */
        context[len] = '\0';
        /* We have a legit context */
        rc = security_context_to_sid(context, &sid);
#if 0
        printk(KERN_WARNING "%s:  context_to_sid(%s:%d) "
               "returned 0x%x for dev=%s ino=%ld\n",
               __FUNCTION__, context, len, sid,
               inode->i_sb->s_id, inode->i_ino);
#endif
        if (rc) {
#if 0
            printk(KERN_WARNING "%s:  context_to_sid(%s) "
                   "returned %d for dev=%s ino=%ld\n",
                   __FUNCTION__, context, -rc,
                   inode->i_sb->s_id, inode->i_ino);
#endif
            /* Leave with the unlabeled SID */
            sid = SAMPLE_IGNORE;
        }
    }
    kfree(context);
    return sid;

out:
    return SAMPLE_IGNORE;
}


static u32 get_task_sid(struct task_struct *task)
{
    return (u32) task->security;
}


static u32 get_inode_sid(struct inode *inode)
{
    struct dentry *dentry;

    dentry = d_find_alias(inode);
    return inode_init_with_dentry(dentry, inode);
}


static int inode_has_perm(struct task_struct *task,
          struct inode *inode, int ops,
          struct vfsmount *mnt, struct dentry *dentry)
{
    u32 ssid = get_task_sid(task);
    u32 osid = get_inode_sid(inode);
    int rtn;
    char *pname = (char *)NULL, *buf;
    int len = PATHLEN;

        /* get pathname for exceptions and printing */
    buf = kmalloc(len, GFP_KERNEL);

    if (buf && dentry && mnt) {  // && nd->dentry && nd->mnt
        buf = memset(buf, '\0', len);
        pname = d_path(dentry, mnt, buf, len-1);
#if 0
        if (ssid && osid) {
            printk(KERN_WARNING "%s: path: 0x%x with val %s; buf 0x%x with val %s\n",
                   __FUNCTION__, pname, pname, buf, buf);
        }
#endif
    }

        /* exceptions - no authorization */
    if (pname && (len >= 4)) {
        if (!strncmp(buf, "/dev", 4))  // allow /dev
            goto done;
        if (!strncmp(buf, "/proc", 5)) // allow /proc
            goto done;
        if (!strncmp(buf, "/var", 4)) // allow /var - no xattr
            goto done;
    }

        /* YOUR CODE: do authorize */
        rtn=has_perm(ssid,osid,ops);
        /* print relevant decisions: for our processes or on our objects */
    if ( ssid && osid ){
        if ( !rtn ) {
            printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x "
                   "NOT authorized (%d) for inode osid 0x%x (file:%s) for ops 0x%x\n",
                   __FUNCTION__, current->pid, ssid, rtn, osid,
                   (pname ? pname : "unk?"), ops);
        }
        else {
            printk(KERN_WARNING "%s: target task pid=%d of ssid 0x%x "
                   "authorized for inode osid:ops 0x%x:0x%x (file:%s) \n",
                   __FUNCTION__, current->pid, ssid, osid, ops,
                   (pname ? pname : "unk?"));
        }
    }

done:
    kfree(buf);
    return rtn;
}


static int sample_inode_permission(struct inode *inode, int mask,
               struct nameidata *nd)
{
    struct vfsmount *mnt = (struct vfsmount *)NULL;
    struct dentry *dentry = (struct dentry *)NULL;
    int rtn;

/* no need to check if no mask (ops) */
    if (!mask) {
        /* No permission to check.  Existence test. */
        return 0;
    }

    /*  Prepare call to inode_has_perm */
    /* get the dentry for inode_has_perm */
    //here i intitalze dentry and mnt to call inode_has_perm function
    if ( nd ) {
        mnt = nd->mnt;//CHECK POINTERS ARE CORRECT ARE NOT.
        dentry = nd->dentry; //assigning dentry here
        //!!!! could lead to SEGFAULT TEST HERE-ali
    }

    rtn = inode_has_perm(current, inode, mask, mnt, dentry);

    return 0; /* permissive */
}



/* Label process based on xattr of executable file */

static int sample_bprm_set_security(struct linux_binprm *bprm)
{
    struct inode *inode = bprm->file->f_dentry->d_inode; //getting my file dentry
    /* YOUR CODE: Determine the label for the new process */
    //getting the osid from inode , this should return the correct attrs
    u32 osid = get_inode_sid(inode);
    //check if write function call ?

    /* YOUR CODE: Determine label for a new process */

    /* Print label of new process */
    if (osid) {
        current->security = (void *)osid;
        printk(KERN_WARNING "%s: set task pid=%d of ssid 0x%x\n",
               __FUNCTION__, current->pid, osid);
    }

    return 0;
}


static int sample_inode_init_security(struct inode *inode, struct inode *dir,
                   char **name, void **value,
                   size_t *len)
{
    u32 ssid = get_task_sid(current);
    char *namep, *valuep;

    if (!inode || !dir)
        return -EOPNOTSUPP;

    if (ssid == SAMPLE_IGNORE)
        return -EOPNOTSUPP;

    printk(KERN_WARNING "%s: pid %d:0x%x creating a new file\n",
           __FUNCTION__, current->pid, ssid);

/* get attribute name */
    namep = kstrdup(XATTR_SAMPLE_SUFFIX, GFP_KERNEL);
    if (!namep)
        return -ENOMEM;
    *name = namep;

/* set xattr value and length */
    if (ssid == SAMPLE_TRUSTED) {
        valuep = kstrdup("trusted", GFP_KERNEL);
        *len = 8;
        printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates Trusted object\n",
               __FUNCTION__, current->pid, ssid);
    }
    else if (ssid == SAMPLE_UNTRUSTED) {
        valuep = kstrdup("untrusted", GFP_KERNEL);
        *len = 10;
        printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates UN-Trusted object\n",
               __FUNCTION__, current->pid, ssid);
    }

    if (!valuep)
        return -ENOMEM;
    *value = valuep;

    return 0;
}


int sample_inode_setxattr (struct dentry *dentry, char *name, void *value,
                      size_t size, int flags)
{
    struct inode *inode;
    u32 mask = MAY_WRITE;
    struct vfsmount *mnt = (struct vfsmount *)NULL;
    u32 ssid, osid;
    int rtn;

    if (!strncmp(name, XATTR_NAME_SAMPLE,
             sizeof(XATTR_NAME_SAMPLE) - 1)) { //null value passed, may cause segfaults here!!!

        return 0;
    }

    if (!dentry || !dentry->d_inode) { //null values passed
        return -EPERM;
    }
    //YOUR CODE:
    //getting inputs for inode_has_perm
    inode = dentry->d_inode;
    ssid = get_task_sid(current);
    osid = get_inode_sid(inode);

    /* Prepare invocation of inode_has_perm */

        /* record attribute setting request before authorization */
    if (ssid && osid) {
        printk(KERN_WARNING "%s: task pid=%d of label 0x%x setting attribute %s"
               "for object of label 0x%x\n",
               __FUNCTION__, current->pid, ssid, (name ? name : "unk?"), osid);
    }

    rtn = inode_has_perm(current, inode, mask, mnt, dentry);

    return 0;
}


int sample_inode_create (struct inode *inode, struct dentry *dentry,
                               int mask)
{
    struct vfsmount *mnt;
    int rtn;

    /* YOUR CODE: Prepare invocation of inode_has_perm */

    rtn = inode_has_perm(current, inode, mask, mnt, dentry);

        return 0;
}


int sample_file_permission (struct file *file, int mask)
{
        struct inode *inode;
    struct vfsmount *mnt;
    struct dentry *dentry;
    int rtn;

    /* YOUR CODE: Prepare invocation of inode_has_perm */

    rtn = inode_has_perm(current, inode, mask, mnt, dentry);

    return 0; /* permissive */
}


static struct security_operations sample_ops = {
    .inode_permission =     sample_inode_permission,
    .bprm_set_security =        sample_bprm_set_security,
    .inode_init_security =      sample_inode_init_security,
    .inode_setxattr =       sample_inode_setxattr,
    .inode_create =         sample_inode_create,
    .file_permission =      sample_file_permission,
#if 0
    .ptrace_access_check =      selinux_ptrace_access_check,
    .ptrace_traceme =       selinux_ptrace_traceme,
    .capget =           selinux_capget,
    .capset =           selinux_capset,
    .sysctl =           selinux_sysctl,
    .capable =          selinux_capable,
    .quotactl =         selinux_quotactl,
    .quota_on =         selinux_quota_on,
    .syslog =           selinux_syslog,
    .vm_enough_memory =     selinux_vm_enough_memory,

    .netlink_send =         selinux_netlink_send,
    .netlink_recv =         selinux_netlink_recv,

    .bprm_set_creds =       selinux_bprm_set_creds,
    .bprm_committing_creds =    selinux_bprm_committing_creds,
    .bprm_committed_creds =     selinux_bprm_committed_creds,
    .bprm_secureexec =      selinux_bprm_secureexec,

    .sb_alloc_security =        selinux_sb_alloc_security,
    .sb_free_security =     selinux_sb_free_security,
    .sb_copy_data =         selinux_sb_copy_data,
    .sb_kern_mount =        selinux_sb_kern_mount,
    .sb_show_options =      selinux_sb_show_options,
    .sb_statfs =            selinux_sb_statfs,
    .sb_mount =         selinux_mount,
    .sb_umount =            selinux_umount,
    .sb_set_mnt_opts =      selinux_set_mnt_opts,
    .sb_clone_mnt_opts =        selinux_sb_clone_mnt_opts,
    .sb_parse_opts_str =        selinux_parse_opts_str,


    .inode_alloc_security =     selinux_inode_alloc_security,
    .inode_free_security =      selinux_inode_free_security,
    .inode_init_security =      selinux_inode_init_security,
    .inode_create =         selinux_inode_create,
    .inode_link =           selinux_inode_link,
    .inode_unlink =         selinux_inode_unlink,
    .inode_symlink =        selinux_inode_symlink,
    .inode_mkdir =          selinux_inode_mkdir,
    .inode_rmdir =          selinux_inode_rmdir,
    .inode_mknod =          selinux_inode_mknod,
    .inode_rename =         selinux_inode_rename,
    .inode_readlink =       selinux_inode_readlink,
    .inode_follow_link =        selinux_inode_follow_link,
    .inode_permission =     selinux_inode_permission,
    .inode_setattr =        selinux_inode_setattr,
    .inode_getattr =        selinux_inode_getattr,
    .inode_setxattr =       selinux_inode_setxattr,
    .inode_post_setxattr =      selinux_inode_post_setxattr,
    .inode_getxattr =       selinux_inode_getxattr,
    .inode_listxattr =      selinux_inode_listxattr,
    .inode_removexattr =        selinux_inode_removexattr,
    .inode_getsecurity =        selinux_inode_getsecurity,
    .inode_setsecurity =        selinux_inode_setsecurity,
    .inode_listsecurity =       selinux_inode_listsecurity,
    .inode_getsecid =       selinux_inode_getsecid,

    .file_permission =      selinux_file_permission,
    .file_alloc_security =      selinux_file_alloc_security,
    .file_free_security =       selinux_file_free_security,
    .file_ioctl =           selinux_file_ioctl,
    .file_mmap =            selinux_file_mmap,
    .file_mprotect =        selinux_file_mprotect,
    .file_lock =            selinux_file_lock,
    .file_fcntl =           selinux_file_fcntl,
    .file_set_fowner =      selinux_file_set_fowner,
    .file_send_sigiotask =      selinux_file_send_sigiotask,
    .file_receive =         selinux_file_receive,

    .dentry_open =          selinux_dentry_open,

    .task_create =          selinux_task_create,
    .cred_alloc_blank =     selinux_cred_alloc_blank,
    .cred_free =            selinux_cred_free,
    .cred_prepare =         selinux_cred_prepare,
    .cred_transfer =        selinux_cred_transfer,
    .kernel_act_as =        selinux_kernel_act_as,
    .kernel_create_files_as =   selinux_kernel_create_files_as,
    .kernel_module_request =    selinux_kernel_module_request,
    .task_setpgid =         selinux_task_setpgid,
    .task_getpgid =         selinux_task_getpgid,
    .task_getsid =          selinux_task_getsid,
    .task_getsecid =        selinux_task_getsecid,
    .task_setnice =         selinux_task_setnice,
    .task_setioprio =       selinux_task_setioprio,
    .task_getioprio =       selinux_task_getioprio,
    .task_setrlimit =       selinux_task_setrlimit,
    .task_setscheduler =        selinux_task_setscheduler,
    .task_getscheduler =        selinux_task_getscheduler,
    .task_movememory =      selinux_task_movememory,
    .task_kill =            selinux_task_kill,
    .task_wait =            selinux_task_wait,
    .task_to_inode =        selinux_task_to_inode,

    .ipc_permission =       selinux_ipc_permission,
    .ipc_getsecid =         selinux_ipc_getsecid,

    .msg_msg_alloc_security =   selinux_msg_msg_alloc_security,
    .msg_msg_free_security =    selinux_msg_msg_free_security,

    .msg_queue_alloc_security = selinux_msg_queue_alloc_security,
    .msg_queue_free_security =  selinux_msg_queue_free_security,
    .msg_queue_associate =      selinux_msg_queue_associate,
    .msg_queue_msgctl =     selinux_msg_queue_msgctl,
    .msg_queue_msgsnd =     selinux_msg_queue_msgsnd,
    .msg_queue_msgrcv =     selinux_msg_queue_msgrcv,

    .shm_alloc_security =       selinux_shm_alloc_security,
    .shm_free_security =        selinux_shm_free_security,
    .shm_associate =        selinux_shm_associate,
    .shm_shmctl =           selinux_shm_shmctl,
    .shm_shmat =            selinux_shm_shmat,

    .sem_alloc_security =       selinux_sem_alloc_security,
    .sem_free_security =        selinux_sem_free_security,
    .sem_associate =        selinux_sem_associate,
    .sem_semctl =           selinux_sem_semctl,
    .sem_semop =            selinux_sem_semop,

    .d_instantiate =        selinux_d_instantiate,

    .getprocattr =          selinux_getprocattr,
    .setprocattr =          selinux_setprocattr,

    .secid_to_secctx =      selinux_secid_to_secctx,
    .secctx_to_secid =      selinux_secctx_to_secid,
    .release_secctx =       selinux_release_secctx,
    .inode_notifysecctx =       selinux_inode_notifysecctx,
    .inode_setsecctx =      selinux_inode_setsecctx,
    .inode_getsecctx =      selinux_inode_getsecctx,

    .unix_stream_connect =      selinux_socket_unix_stream_connect,
    .unix_may_send =        selinux_socket_unix_may_send,

    .socket_create =        selinux_socket_create,
    .socket_post_create =       selinux_socket_post_create,
    .socket_bind =          selinux_socket_bind,
    .socket_connect =       selinux_socket_connect,
    .socket_listen =        selinux_socket_listen,
    .socket_accept =        selinux_socket_accept,
    .socket_sendmsg =       selinux_socket_sendmsg,
    .socket_recvmsg =       selinux_socket_recvmsg,
    .socket_getsockname =       selinux_socket_getsockname,
    .socket_getpeername =       selinux_socket_getpeername,
    .socket_getsockopt =        selinux_socket_getsockopt,
    .socket_setsockopt =        selinux_socket_setsockopt,
    .socket_shutdown =      selinux_socket_shutdown,
    .socket_sock_rcv_skb =      selinux_socket_sock_rcv_skb,
    .socket_getpeersec_stream = selinux_socket_getpeersec_stream,
    .socket_getpeersec_dgram =  selinux_socket_getpeersec_dgram,
    .sk_alloc_security =        selinux_sk_alloc_security,
    .sk_free_security =     selinux_sk_free_security,
    .sk_clone_security =        selinux_sk_clone_security,
    .sk_getsecid =          selinux_sk_getsecid,
    .sock_graft =           selinux_sock_graft,
    .inet_conn_request =        selinux_inet_conn_request,
    .inet_csk_clone =       selinux_inet_csk_clone,
    .inet_conn_established =    selinux_inet_conn_established,
    .req_classify_flow =        selinux_req_classify_flow,
    .tun_dev_create =       selinux_tun_dev_create,
    .tun_dev_post_create =      selinux_tun_dev_post_create,
    .tun_dev_attach =       selinux_tun_dev_attach,

#ifdef CONFIG_SECURITY_NETWORK_XFRM
    .xfrm_policy_alloc_security =   selinux_xfrm_policy_alloc,
    .xfrm_policy_clone_security =   selinux_xfrm_policy_clone,
    .xfrm_policy_free_security =    selinux_xfrm_policy_free,
    .xfrm_policy_delete_security =  selinux_xfrm_policy_delete,
    .xfrm_state_alloc_security =    selinux_xfrm_state_alloc,
    .xfrm_state_free_security = selinux_xfrm_state_free,
    .xfrm_state_delete_security =   selinux_xfrm_state_delete,
    .xfrm_policy_lookup =       selinux_xfrm_policy_lookup,
    .xfrm_state_pol_flow_match =    selinux_xfrm_state_pol_flow_match,
    .xfrm_decode_session =      selinux_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
    .key_alloc =            selinux_key_alloc,
    .key_free =         selinux_key_free,
    .key_permission =       selinux_key_permission,
    .key_getsecurity =      selinux_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
    .audit_rule_init =      selinux_audit_rule_init,
    .audit_rule_known =     selinux_audit_rule_known,
    .audit_rule_match =     selinux_audit_rule_match,
    .audit_rule_free =      selinux_audit_rule_free,
#endif

#endif /* sample if 0 */
};

static __init int sample_init(void)
{
    if (register_security (&sample_ops)) {
        printk("Sample: Unable to register with kernel.\n");
        return 0;
    }
 
    printk(KERN_INFO "Sample:  Initializing.\n");

    return 0;
}

static __exit void sample_exit(void)
{
    printk(KERN_INFO "Sample: Exiting.\n");

    unregister_security(&sample_ops);
}


module_init(sample_init);
module_exit(sample_exit);
