/*
 * allocate the SELinux part of blank credentials
 */
static int selinux_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct task_security_struct *tsec;

	tsec = kzalloc(sizeof(struct task_security_struct), gfp);
	if (!tsec)
		return -ENOMEM;

	cred->security = tsec;
	return 0;
}

/*
 * detach and free the LSM part of a set of credentials
 */
static void selinux_cred_free(struct cred *cred)
{
	struct task_security_struct *tsec = cred->security;

	/*
	 * cred->security == NULL if security_cred_alloc_blank() or
	 * security_prepare_creds() returned an error.
	 */
	BUG_ON(cred->security && (unsigned long) cred->security < PAGE_SIZE);
	cred->security = (void *) 0x7UL;
	kfree(tsec);
}

/*
 * prepare a new set of credentials for modification
 */
static int selinux_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	const struct task_security_struct *old_tsec;
	struct task_security_struct *tsec;

	old_tsec = old->security;

	tsec = kmemdup(old_tsec, sizeof(struct task_security_struct), gfp);
	if (!tsec)
		return -ENOMEM;

	new->security = tsec;
	return 0;
}
