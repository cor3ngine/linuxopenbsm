//#include <stdio.h>
//#include <stdlib.h>

typedef struct {
	u_int32_t	auid;
	u_int32_t	euid;
	u_int32_t	egid;
	u_int32_t	ruid;
	u_int32_t	rgid;
	u_int32_t	pid;
	u_int32_t	sid;
//	au_tid32_t	tid;
} au_subject32_t;

struct tokenstr {
	u_char	id;
	u_char *data;
	size_t	len;
	union {
		au_subject32_t	subj32;
	} tt;
};

#define READ_TOKEN_BYTES(buf, len, dest, size, bytesread, err) do {     \
        if (bytesread + size > len) {                                   \
                err = 1;                                                \
        } else {                                                        \
                memcpy(dest, buf + bytesread, size);                    \
                bytesread += size;                                      \
        }                                                               \
} while (0)

#define READ_TOKEN_U_CHAR(buf, len, dest, bytesread, err) do {          \
        if (bytesread + sizeof(u_char) <= len) {                        \
                dest = buf[bytesread];                                  \
                bytesread += sizeof(u_char);                            \
        } else                                                          \
                err = 1;                                                \
} while (0)

#define READ_TOKEN_U_INT16(buf, len, dest, bytesread, err) do {         \
        if (bytesread + sizeof(u_int16_t) <= len) {                     \
                dest = be16dec(buf + bytesread);                        \
                bytesread += sizeof(u_int16_t);				\
        } else                                                          \
                err = 1;                                                \
} while (0)

#define READ_TOKEN_U_INT32(buf, len, dest, bytesread, err) do {         \
        if (bytesread + sizeof(u_int32_t) <= len) {                     \
                dest = be32dec(buf + bytesread);                        \
                bytesread += sizeof(u_int32_t);                         \
        } else                                                          \
                err = 1;                                                \
} while (0)

#define READ_TOKEN_U_INT64(buf, len, dest, bytesread, err) do {         \
        if (bytesread + sizeof(u_int64_t) <= len) {                     \
                dest = be64dec(buf + bytesread);                        \
                bytesread += sizeof(u_int64_t);                         \
        } else                                                          \
                err = 1;                                                \
} while (0)

#define SET_PTR(buf, len, ptr, size, bytesread, err) do {               \
        if ((bytesread) + (size) > (len))                               \
                (err) = 1;                                              \
        else {                                                          \
                (ptr) = (buf) + (bytesread);                            \
                (bytesread) += (size);                                  \
        }                                                               \
} while (0)

/* FIXME: the next functions are stored in sys/endian.h on FreeBSD */

static inline uint16_t be16dec(const void *pp)
{
	unsigned char const *p = (unsigned char const *)pp;
	
	return ((p[0] << 8) | p[1]);
}

static inline uint32_t be32dec(const void *pp)
{
	unsigned char const *p = (unsigned char const *)pp;

	return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline uint64_t be64dec(const void *pp)
{
	unsigned char const *p = (unsigned char const *)pp;

	return (((uint64_t)be32dec(p) << 32) | be32dec(p + 4));
}
