
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

/* Blocking return codes */
#define ALLOW_OP 0
#define BIBA_NO_WRITE_UP 1
#define NO_CWL_NO_READ_DOWN 2
