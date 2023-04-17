//
//  ESFTypes.swift
//  ESLogger
//
//  Created by nub on 2/1/23.
//  Copyright (c) 2023 nubco, llc
//


// Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/
//   ESMessage.h
//   ESTypes.h
public struct ESMessage: Codable, Sendable {
    public let schema_version: Int
    public let version: Int
    public let time: String
    public let mach_time: Int
    public let thread: ESThread?
    public let seq_num: Int
    public let global_seq_num: Int
    public let action_type: ActionType
    public let action: action_inner
    public let deadline: Int? // only used for AUTH events
    
    // structure does not match whats in SDK header files (using what's found in JSON itself from eslogger)
    public struct action_inner: Codable, Sendable {
        // ignoring es_event_id which is a reserved[32] uint8 - public let auth: ESEventId?
        // eslogger calls this result, but the public struct calls it notify public let notify: ESResult?
        public let result: ESResult?
    }

    public let event_type: EventType
    public let event: ESEvent
    public let process: ESProcess
}

public struct ESProcess: Codable, Sendable {
    public let audit_token: AuditToken
    public let ppid: Int
    public let original_ppid: Int
    public let group_id: Int
    public let session_id: Int
    public let codesigning_flags: CodeSigningFlags
    public let is_platform_binary: Bool
    public let is_es_client: Bool
    public let cdhash: String
    public let signing_id: String?
    public let team_id: String?
    public let executable: ESFile
    public let tty: ESFile?
    public let start_time: String
    public let responsible_audit_token: AuditToken
    public let parent_audit_token: AuditToken
}

public struct ESFile: Codable, Sendable {
    public let path: String
    public let stat: Stat
    public let path_truncated: Bool
}

public struct ESThread: Codable, Sendable {
    public let thread_id: Int
}

public struct Stat: Codable, Sendable {
    public let st_blocks: Int
    public let st_blksize: Int
    public let st_rdev: Int
    public let st_dev: Int
    public let st_uid: Int
    public let st_gid: Int
    public let st_ino: Int
    public let st_birthtimespec: String
    public let st_flags: Int
    public let st_nlink: Int
    public let st_mtimespec: String
    public let st_ctimespec: String
    public let st_size: Int
    public let st_gen: Int
    public let st_mode: Int
    public let st_atimespec: String
}

public struct AuditToken: Codable, Sendable {
    public let asid: Int
    public let pidversion: Int
    public let ruid: Int
    public let euid: Int
    public let rgid: Int
    public let auid: Int
    public let egid: Int
    public let pid: Int
}

// eslogger uses statfs64 not statfs but calls it statfs
public struct Statfs: Codable, Sendable {
    public let f_bsize: Int
    public let f_iosize: Int
    public let f_blocks: Int
    public let f_bfree: Int
    public let f_bavail: Int
    public let f_files: Int
    public let f_ffree: Int
    public let f_fsid: [Int]
    public let f_owner: Int
    public let f_type: Int
    public let f_flags: Int
    public let f_fssubtype: Int
    public let f_fstypename: String
    public let f_mntonname: String
    public let f_mntfromname: String
}

// sys/signal.h
public enum SignalType: Int, Codable, Sendable {
    case SIGZERO=0, // this is not in signal.h header or man page, but is in the events
         SIGHUP=1, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGPOLL, SIGFPE,
         SIGKILL, SIGBUS, SIGSEGV, SIGSYS, SIGPIPE, SIGALRM, SIGTERM, SIGURG,
         SIGSTOP, SIGTSTP, SIGCONT, SIGCHLD, SIGTTIN, SIGTTOU, SIGIO, SIGXCPU,
         SIGXFSZ, SIGVTARLM, SIGPROF, SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
}

public struct ESAuthenticationOd: Codable, Sendable {
    public let instigator: ESProcess
    public let record_type: String
    public let record_name: String
    public let node_name: String
    public let db_path: String?
}

public struct ESAuthenticationTouchId: Codable, Sendable {
    public let instigator: ESProcess
    public let touchid_mode: ESTouchMode
    public let uid: Int?
}

public struct ESAuthenticationToken: Codable, Sendable {
    public let instigator: ESProcess
    public let pubkey_hash: String
    public let token_id: String
    public let kerberos_principle: String?
}

public enum ESAutoUnlockType: Int, Codable, Sendable {
    case ES_AUTO_UNLOCK_MACHINE_UNLOCK=1,
         ES_AUTO_UNLOCK_AUTH_PROMPT
}

public struct ESAuthenticationAutoUnlock: Codable, Sendable {
    public let username: String
    public let type: ESAutoUnlockType
}

public struct ESThreadState: Codable, Sendable {
    public let flavor: Int
    // public let state: Data? - exec has es_token_t but it's omitted - here it's null.
}


public struct ESBTMLaunchItem: Codable, Sendable {
    public let item_type: ESBTMItemType
    public let legacy: Bool
    public let managed: Bool
    public let uid: Int
    public let item_url: String
    public let app_url: String?
}

public struct ESFD: Codable, Sendable {
    public let fd: Int
    public let fdtype: Int
    public let pipe: pipe_inner?
    
    public struct pipe_inner: Codable, Sendable {
        public let pipe_id: Int
    }
}

// sys/attr.h (removed reserved it's only for structure alignment)
public struct AttrList: Codable, Sendable {
    public let bitmapcount: Int
    public let commonattr: Int
    public let volattr: Int
    public let dirattr: Int
    public let fileattr: Int
    public let forkattr: Int
}

public enum ESResultType: Int, Codable, Sendable {
    case ES_RESULT_TYPE_AUTH=0,
         ES_RESULT_TYPE_FLAGS
}

public enum ESAuthResultType: Int, Codable, Sendable {
    case ES_AUTH_RESULT_ALLOW=0,
         ES_AUTH_RESULT_DENY
}

public struct ESResult: Codable, Sendable {
    public let result_type: ESResultType
    public let result: result_inner
    
    public struct result_inner: Codable, Sendable {
        public let auth: ESAuthResultType?
        public let flags: Int?
    }
}

public enum ActionType: Int, Codable, Sendable {
    case ES_ACTION_TYPE_AUTH=0
    , ES_ACTION_TYPE_NOTIFY
}

public enum ESSetOrClear: Int, Codable, Sendable {
    case ES_SET=0,
         ES_CLEAR
}

public enum ESProcCheckType: Int, Codable, Sendable {
    case ES_PROC_CHECK_TYPE_LISTPIDS=1,
         ES_PROC_CHECK_TYPE_PIDINFO,
         ES_PROC_CHECK_TYPE_PIDFDINFO,
         ES_PROC_CHECK_TYPE_KERNMSGBUF,
         ES_PROC_CHECK_TYPE_SETCONTROL,
         ES_PROC_CHECK_TYPE_PIDFILEPORTINFO,
         ES_PROC_CHECK_TYPE_TERMINATE,
         ES_PROC_CHECK_TYPE_DIRTYCONTROL,
         ES_PROC_CHECK_TYPE_PIDRUSAGE,
         ES_PROC_CHECK_TYPE_UDATA_INFO=0xe
}

public enum ESDestinationType: Int, Codable, Sendable {
    case ES_DESTINATION_TYPE_EXISTING_FILE=0,
         ES_DESTINATION_TYPE_NEW_PATH
}

public enum ESProcSuspendResumeType: Int, Codable, Sendable {
    case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND = 0,
         ES_PROC_SUSPEND_RESUME_TYPE_RESUME = 1,
         ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS = 3
}

public enum ESGetTaskType: Int, Codable, Sendable {
    case ES_GET_TASK_TYPE_TASK_FOR_PID=0,
         ES_GET_TASK_TYPE_EXPOSE_TASK,
         ES_GET_TASK_TYPE_IDENTITY_TOKEN
}

public enum ESTouchMode: Int, Codable, Sendable {
    case ES_TOUCHID_MODE_VERIFICATION=0,
         ES_TOUCHID_MODE_IDENTIFICATION
}

public enum ESAuthenticationType: Int, Codable, Sendable {
    case ES_AUTHENTICATION_TYPE_OD=0,
         ES_AUTHENTICATION_TYPE_TOUCHID,
         ES_AUTHENTICATION_TYPE_TOKEN,
         ES_AUTHENTICATION_TYPE_AUTO_UNLOCK,
         ES_AUTHENTICATION_TYPE_LAST
}

public enum ESAddressType: Int, Codable, Sendable {
    case ES_ADDRESS_TYPE_NONE=0,
         ES_ADDRESS_TYPE_IPV4,
         ES_ADDRESS_TYPE_IPV6,
         ES_ADDRESS_TYPE_NAMED_SOCKET
}

public enum ESBTMItemType: Int, Codable, Sendable {
    case ES_BTM_ITEM_TYPE_USER_ITEM=0,
         ES_BTM_ITEM_TYPE_APP,
         ES_BTM_ITEM_TYPE_LOGIN_ITEM,
         ES_BTM_ITEM_TYPE_AGENT,
         ES_BTM_ITEM_TYPE_DAEMON
}

public enum ESOpenSSHLoginResultType: Int, Codable, Sendable {
    case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES = 0,
         ES_OPENSSH_LOGIN_ROOT_DENIED,
         ES_OPENSSH_AUTH_SUCCESS,
         ES_OPENSSH_AUTH_FAIL_NONE,
         ES_OPENSSH_AUTH_FAIL_PASSWD,
         ES_OPENSSH_AUTH_FAIL_KBDINT,
         ES_OPENSSH_AUTH_FAIL_PUBKEY,
         ES_OPENSSH_AUTH_FAIL_HOSTBASED,
         ES_OPENSSH_AUTH_FAIL_GSSAPI,
         ES_OPENSSH_INVALID_USER
}

// sys/socket.h
public enum ESSocketType: Int, Codable, Sendable {
    case SOCK_STREAM=1,
         SOCK_DGRAM,
         SOCK_RAW,
         SOCK_RDM,
         SOCK_SEQPACKET
}

//sys/socket.h
public enum ESSocketDomain: Int, Codable, Sendable {
    case AF_UNSPEC=0,
         AF_LOCAL, AF_INET, AF_IMPLINK, AF_PUP,
         AF_CHAOS, AF_NS, AF_ISO, AF_ECMA,
         AF_DATAKIT, AF_CCITT, AF_SNA, AF_DECnet,
         AF_DLI, AF_LAT, AF_HYLINK, AF_APPLETALK,
         AF_ROUTE, AF_LINK, pseudo_AF_XTP, AF_COIP,
         AF_CNT, pseudo_AF_RTIP, AF_IPX, AF_SIP,
         pseudo_AF_PIP, AF_INVALID26, AF_NDRV, AF_ISDN,
         pseudo_AF_KEY, AF_INET6, AF_NATM, AF_SYSTEM,
         AF_NETBIOS, AF_PPP, pseudo_AF_HDRCMPLT, AF_RESERVED_36,
         AF_IEEE80211, AF_UTUN, AF_INVALID39, AF_VSOCK,
         AF_MAX
}

//netinet/in.h
public enum ESIPProtocol: Int, Codable, Sendable {
    case IPPROTO_IP=0,
         IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_GGP, IPPROTO_IPV4,
         IPPROTO_TCP=6, IPPROTO_ST, IPPROTO_EGP, IPPROTO_PIGP,
         IPPROTO_RCCMON, IPPROTO_NVPII, IPPROTO_PUP, IPPROTO_ARGUS,
         IPPROTO_EMCON, IPPROTO_XNET, IPPROTO_CHAOS, IPPROTO_UDP,
         IPPROTO_MUX, IPPROTO_MEAS, IPPROTO_HMP, IPPROTO_PRM,
         IPPROTO_IDP, IPPROTO_TRUNK1, IPPROTO_TRUNK2, IPPROTO_LEAF1,
         IPPROTO_LEAF2, IPPROTO_RDP, IPPROTO_IRTP, IPPROTO_TP,
         IPPROTO_BLT, IPPROTO_NSP, IPPROTO_INP, IPPROTO_SEP,
         IPPROTO_3PC, IPPROTO_IDPR, IPPROTO_XTP, IPPROTO_DDP,
         IPPROTO_CMTP, IPPROTO_TPXX, IPPROTO_IL, IPPROTO_IPV6,
         IPPROTO_SDRP, IPPROTO_ROUTING, IPPROTO_FRAGMENT, IPPROTO_IDRP,
         IPPROTO_RSVP, IPPROTO_GRE, IPPROTO_MHRP, IPPROTO_BHA,
         IPPROTO_ESP, IPPROTO_AH, IPPROTO_INLSP, IPPROTO_SWIPE,
         IPPROTO_NHRP,
         IPPROTO_ICMPV6=58, IPPROTO_NONE, IPPROTO_DSTOPTS, IPPROTO_AHIP,
         IPPROTO_CFTP, IPPROTO_HELLO, IPPROTO_SATEXPAK, IPPROTO_KRYPTOLAN,
         IPPROTO_RVD, IPPROTO_IPPC, IPPROTO_ADFS, IPPROTO_SATMON,
         IPPROTO_VISA, IPPROTO_IPCV, IPPROTO_CPNX, IPPROTO_CPHB,
         IPPROTO_WSN, IPPROTO_PVP, IPPROTO_BRSATMON, IPPROTO_ND,
         IPPROTO_WBMON, IPPROTO_WBEXPAK, IPPROTO_EON, IPPROTO_VMTP,
         IPPROTO_SVMTP, IPPROTO_VINES, IPPROTO_TTP, IPPROTO_IGP,
         IPPROTO_DGP, IPPROTO_TCF, IPPROTO_IGRP, IPPROTO_OSPFIGP,
         IPPROTO_SRPC, IPPROTO_LARP, IPPROTO_MTP, IPPROTO_AX25,
         IPPROTO_IPEIP, IPPROTO_MICP, IPPROTO_SCCSP, IPPROTO_ETHERIP,
         IPPROTO_ENCAP, IPPROTO_APES, IPPROTO_GMTP,
         IPPROTO_PIM=103,
         IPPROTO_IPCOMP=108,
         IPPROTO_PGM=113,
         IPPROTO_SCTP=132,
         IPPROTO_DIVERT=254,
         IPPROTO_RAW=255,
         IPPROTO_MAX=256
}

// kern/cs_blobs.h
public struct CodeSigningFlags: OptionSet, Codable, Hashable, CustomStringConvertible, Sendable {
    public let rawValue: Int
    
    public init(rawValue: Int) {
        self.rawValue = rawValue
    }
    
    public func isSigned() -> Bool {
        return self.contains(.CS_SIGNED)
    }
    
    /*
     public func hasEntitlements() -> Bool {
     return !self.isDisjoint(with: self.CS_ENTITLEMENT_FLAGS)
     }
     */
    
    public static let CS_VALID = CodeSigningFlags(rawValue: 1 << 0)
    public static let CS_ADHOC = CodeSigningFlags(rawValue: 1 << 1)
    public static let CS_GET_TASK_ALLOW = CodeSigningFlags(rawValue: 1 << 2)
    public static let CS_INSTALLER = CodeSigningFlags(rawValue: 1 << 3)
    
    public static let CS_HARD = CodeSigningFlags(rawValue: 1 << 8)
    public static let CS_KILL = CodeSigningFlags(rawValue: 1 << 9)
    public static let CS_CHECK_EXPIRATION = CodeSigningFlags(rawValue: 1 << 10)
    public static let CS_RESTRICT = CodeSigningFlags(rawValue: 1 << 11)
    
    public static let CS_ALLOWED_MACHO: CodeSigningFlags = [.CS_ADHOC, .CS_HARD, .CS_KILL,
                                                            .CS_CHECK_EXPIRATION, .CS_RESTRICT,
                                                            .CS_ENFORCEMENT, .CS_REQUIRE_LV]
    
    public static let CS_ENFORCEMENT = CodeSigningFlags(rawValue: 1 << 12)
    public static let CS_REQUIRE_LV = CodeSigningFlags(rawValue: 1 << 13)
    public static let CS_ENTITLEMENTS_VALIDATED = CodeSigningFlags(rawValue: 1 << 14)
    public static let CS_NVRAM_UNRESTRICTED = CodeSigningFlags(rawValue: 1 << 15)
    
    public static let CS_EXEC_SET_HARD = CodeSigningFlags(rawValue: 1 << 20)
    public static let CS_EXEC_SET_KILL = CodeSigningFlags(rawValue: 1 << 21)
    public static let CS_EXEC_SET_ENFORCEMENT = CodeSigningFlags(rawValue: 1 << 22)
    public static let CS_EXEC_INHERIT_SIP = CodeSigningFlags(rawValue: 1 << 23)
    
    public static let CS_KILLED = CodeSigningFlags(rawValue: 1 << 24)
    public static let CS_DYLD_PLATFORM = CodeSigningFlags(rawValue: 1 << 25)
    public static let CS_PLATFORM_BINARY = CodeSigningFlags(rawValue: 1 << 26)
    public static let CS_PLATFORM_PATH = CodeSigningFlags(rawValue: 1 << 27)
    public static let CS_DEBUGGED = CodeSigningFlags(rawValue: 1 << 28)
    public static let CS_SIGNED = CodeSigningFlags(rawValue: 1 << 29)
    public static let CS_DEV_CODE = CodeSigningFlags(rawValue: 1 << 30)
    public static let CS_DATAVAULT_CONTROLLER = CodeSigningFlags(rawValue: 1 << 31)
    
    public static let CS_ENTITLEMENT_FLAGS: CodeSigningFlags = [.CS_GET_TASK_ALLOW, .CS_INSTALLER,
                                                                .CS_DATAVAULT_CONTROLLER,
                                                                .CS_NVRAM_UNRESTRICTED]
    
    public var description: String {
        let descriptionStrings: [CodeSigningFlags: String] = [
            .CS_VALID: "CS_VALID",
            .CS_ADHOC: "CS_ADHOC",
            .CS_GET_TASK_ALLOW: "CS_GET_TASK_ALLOW",
            .CS_INSTALLER: "CS_INSTALLER",
            .CS_HARD: "CS_HARD",
            .CS_KILL: "CS_KILL",
            .CS_CHECK_EXPIRATION: "CS_CHECK_EXPIRATION",
            .CS_RESTRICT: "CS_RESTRICT",
            .CS_ENFORCEMENT: "CS_ENFORCEMENT",
            .CS_REQUIRE_LV: "CS_REQUIRE_LV",
            .CS_ENTITLEMENTS_VALIDATED: "CS_ENTITLEMENTS_VALIDATED",
            .CS_NVRAM_UNRESTRICTED: "CS_NVRAM_UNRESTRICTED",
            .CS_EXEC_SET_HARD: "CS_EXEC_SET_HARD",
            .CS_EXEC_SET_KILL: "CS_EXEC_SET_KILL",
            .CS_EXEC_SET_ENFORCEMENT: "CS_EXEC_SET_ENFORCEMENT",
            .CS_EXEC_INHERIT_SIP: "CS_EXEC_INHERIT_SIP",
            .CS_KILLED: "CS_KILLED",
            .CS_DYLD_PLATFORM: "CS_DYLD_PLATFORM",
            .CS_PLATFORM_BINARY: "CS_PLATFORM_BINARY",
            .CS_PLATFORM_PATH: "CS_PLATFORM_PATH",
            .CS_DEBUGGED: "CS_DEBUGGED",
            .CS_SIGNED: "CS_SIGNED",
            .CS_DEV_CODE: "CS_DEV_CODE",
            .CS_DATAVAULT_CONTROLLER: "CS_DATAVAULT_CONTROLLER",
        ]
        
        var hasStrings: [String] = []
        for (key, value) in descriptionStrings where self.contains(key) {
            hasStrings.append(value)
        }
        
        return hasStrings.joined(separator: " | ")
    }
}



/*
 *
 *  ES Event Notifcation public structures
 *
 */

public struct ESEvent_exec: Codable, Sendable {
    public let target: ESProcess
    // public let reserved0: ESToken - not in eslogger JSON
    
    public let script: ESFile?
    public let cwd: ESFile
    public let last_fd: Int
    public let image_cputype: Int
    public let image_cpusubtype: Int
    
    // eslogger extra fields
    public let env: [String]?
    public let args: [String]?
    public let fds: [ESFD]?
}

public struct ESEvent_open: Codable, Sendable {
    public let fflag: Int
    public let file: ESFile
}

public struct ESEvent_kextload: Codable, Sendable {
    public let identifier: String
}

public struct ESEvent_kextunload: Codable, Sendable {
    public let identifier: String
}

public struct ESEvent_unlink: Codable, Sendable {
    public let target: ESFile
    public let parent_dir: ESFile
}

public struct ESEvent_mmap: Codable, Sendable {
    public let protection: Int
    public let max_protection: Int
    public let flags: Int
    public let file_pos: Int
    public let source: ESFile
}

public struct ESEvent_link: Codable, Sendable {
    public let source: ESFile
    public let target_dir: ESFile
    public let target_filename: String
}

public struct ESEvent_mount: Codable, Sendable {
    public let statfs: Statfs
}

public struct ESEvent_unmount: Codable, Sendable {
    public let statfs: Statfs
}

public struct ESEvent_remount: Codable, Sendable {
    public let statfs: Statfs
}

public struct ESEvent_fork: Codable, Sendable {
    public let child: ESProcess
}

public struct ESEvent_mprotect: Codable, Sendable {
    public let protection: Int
    public let address: Int
    public let size: Int
}

public struct ESEvent_signal: Codable, Sendable {
    public let sig: SignalType
    public let target: ESProcess
}

public struct ESEvent_rename: Codable, Sendable {
    public let source: ESFile
    public let destination_type: ESDestinationType
    public let destination: rename_destination_inner
    
    public struct rename_destination_inner: Codable, Sendable {
        public let existing_file: ESFile?
        public let new_path: rename_new_path_inner?
        
        public struct rename_new_path_inner: Codable, Sendable {
            public let dir: ESFile
            public let filename: String
        }
    }
}

public struct ESEvent_setextattr: Codable, Sendable {
    public let target: ESFile
    public let extattr: String
}

public struct ESEvent_getextattr: Codable, Sendable {
    public let target: ESFile
    public let extattr: String
}

public struct ESEvent_deleteextattr: Codable, Sendable {
    public let target: ESFile
    public let extattr: String
}

public struct ESEvent_setmode: Codable, Sendable {
    public let mode: Int
    public let target: ESFile
}

public struct ESEvent_setflags: Codable, Sendable {
    public let flags: Int
    public let target: ESFile
}

public struct ESEvent_setowner: Codable, Sendable {
    public let uid: Int
    public let gid: Int
    public let target: ESFile
}

public struct ESEvent_close: Codable, Sendable {
    public let modified: Bool
    public let target: ESFile
    public let was_mapped_writable: Bool?
}

public struct ESEvent_create: Codable, Sendable {
    public let destination_type: ESDestinationType
    public let destination: create_destination_inner
    
    public struct create_destination_inner: Codable, Sendable {
        // some of these should be non_null but without union easiest way to to make them nullable
        public let existing_file: ESFile?
        // TODO: (testing) not sure how to evoke this version of event.  creating new file doesn't.
        public let new_path: create_new_path_inner?
        
        public struct create_new_path_inner: Codable, Sendable {
            public let dir: ESFile
            public let filename: String
            public let mode: Int
        }
        // TODO: should likely be acl of type acl_t here.
    }
}

public struct ESEvent_exit: Codable, Sendable {
    public let stat: Int
}

public struct ESEvent_exchangedata: Codable, Sendable {
    public let file1: ESFile
    public let file2: ESFile
}

public struct ESEvent_write: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_truncate: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_chdir: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_stat: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_chroot: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_listextattr: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_iokit_open: Codable, Sendable {
    public let user_client_type: Int
    public let user_client_class: String
}

public struct ESEvent_get_task: Codable, Sendable {
    public let target: ESProcess
    public let type: ESGetTaskType
}

public struct ESEvent_get_task_read: Codable, Sendable {
    public let target: ESProcess
    public let type: ESGetTaskType
}

public struct ESEvent_get_task_inspect: Codable, Sendable {
    public let target: ESProcess
    public let type: ESGetTaskType
}

public struct ESEvent_get_task_name: Codable, Sendable {
    public let target: ESProcess
    public let type: ESGetTaskType
}

public struct ESEvent_getattrlist: Codable, Sendable {
    public let attrlist: AttrList
    public let target: ESFile
}

public struct ESEvent_setattrlist: Codable, Sendable {
    public let attrlist: AttrList
    public let target: ESFile
}

public struct ESEvent_file_provider_update: Codable, Sendable {
    public let source: ESFile
    public let target_path: String
}


public struct ESEvent_file_provider_materialize: Codable, Sendable {
    public let investigator: ESProcess
    public let source: ESFile
    public let target: ESFile
}

public struct ESEvent_readlink: Codable, Sendable {
    public let source: ESFile
}

public struct ESEvent_lookup: Codable, Sendable {
    public let source_dir: ESFile
    public let relative_target: String
}

public struct ESEvent_access: Codable, Sendable {
    public let mode: Int
    public let target: ESFile
}

public struct ESEvent_utimes: Codable, Sendable {
    public let target: ESFile
    public let atime: String
    public let mtime: String
}

public struct ESEvent_clone: Codable, Sendable {
    public let source: ESFile
    public let target_dir: ESFile
    public let target_name: String
}

public struct ESEvent_copyfile: Codable, Sendable {
    public let source: ESFile
    public let target_file: ESFile?
    public let targetdir: ESFile
    public let target_name: String
    public let mode: Int
    public let flags: Int
}

// could create enum for cmd.  there are 77+ of them in fctnl.h...
public struct ESEvent_fcntl: Codable, Sendable {
    public let target: ESFile
    public let cmd: Int
}

public struct ESEvent_readdir: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_fsgetpath: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_settime: Codable, Sendable {
}

public struct ESEvent_dup: Codable, Sendable {
    public let target: ESFile
}

public struct ESEvent_uipc_bind: Codable, Sendable {
    public let dir: ESFile
    public let filename: String
    public let mode: Int
}

public struct ESEvent_uipc_connect: Codable, Sendable {
    public let file: ESFile
    public let domain: ESSocketDomain
    public let type: ESSocketType
    public let proto: ESIPProtocol
    
    // protocol is a reserved word in Swift
    public enum CodingKeys: String, CodingKey, Sendable {
        case file, domain, type, proto="protocol"
    }
}

public struct ESEvent_setacl: Codable, Sendable {
    public let target: ESFile
    public let set_or_clear: ESSetOrClear
    public let acl: setacl_acl_inner
    
    // TODO: (testing) eslogger had exception when pulling sample events
    public struct setacl_acl_inner: Codable, Sendable {
        public let set: Int
    }
}

public struct ESEvent_pty_grant: Codable, Sendable {
    public let dev: Int
}

public struct ESEvent_pty_close: Codable, Sendable {
    public let dev: Int
}

public struct ESEvent_proc_check: Codable, Sendable {
    public let target: ESProcess?
    public let type: ESProcCheckType
    public let flavor: Int
}

public struct ESEvent_searchfs: Codable, Sendable {
    public let attrlist: AttrList
    public let target: ESFile
}

public struct ESEvent_proc_suspend_resume: Codable, Sendable {
    public let target: ESProcess?
    public let type: ESProcSuspendResumeType
}

public struct ESEvent_cs_invalidated: Codable, Sendable {
}

public struct ESEvent_trace: Codable, Sendable {
    public let target: ESProcess
}

public struct ESEvent_remote_thread_create: Codable, Sendable {
    public let target: ESProcess
    public let thread_state: ESThreadState?
}

public struct ESEvent_setuid: Codable, Sendable {
    public let uid: Int
}

public struct ESEvent_setgid: Codable, Sendable {
    public let gid: Int
}

public struct ESEvent_seteuid: Codable, Sendable {
    public let euid: Int
}

public struct ESEvent_setegid: Codable, Sendable {
    public let egid: Int
}

public struct ESEvent_setreuid: Codable, Sendable {
    public let ruid: Int
    public let euid: Int
}

public struct ESEvent_setregid: Codable, Sendable {
    public let rgid: Int
    public let egid: Int
}

public struct ESEvent_authentication: Codable, Sendable {
    public let success: Bool
    public let type: ESAuthenticationType
    public let data: authentication_inner
    
    public struct authentication_inner: Codable, Sendable {
        public let od: ESAuthenticationOd?
        public let touchid: ESAuthenticationTouchId?
        public let token: ESAuthenticationToken?
        public let auto_unlock: ESAuthenticationAutoUnlock?
    }
}

public struct ESEvent_xp_malware_detected: Codable, Sendable {
    public let signature_version: String
    public let malware_identifier: String
    public let incident_identifier: String
    public let detected_path: String
}

public struct ESEvent_xp_malware_remediated: Codable, Sendable {
    public let signature_version: String
    public let malware_identifier: String
    public let incident_identifier: String
    public let action_type: String
    public let success: Bool
    public let result_description: String
    public let remediated_path: String?
    public let remediated_process_audit_token: AuditToken?
}

public struct ESEvent_lw_session_login: Codable, Sendable {
    public let username: String
    public let graphical_session_id: Int
}

public struct ESEvent_lw_session_logout: Codable, Sendable {
    public let username: String
    public let graphical_session_id: Int
}

public struct ESEvent_lw_session_lock: Codable, Sendable {
    public let username: String
    public let graphical_session_id: Int
}

public struct ESEvent_lw_session_unlock: Codable, Sendable {
    public let username: String
    public let graphical_session_id: Int
}

public struct ESEvent_screensharing_attach: Codable, Sendable {
    public let success: Bool
    public let source_address_type: ESAddressType
    public let source_address: String?
    public let viewer_appleid: String?
    public let authentication_type: String
    public let authentication_username: String?
    public let session_username: String?
    public let existing_session: Bool
    public let graphical_session_id: Int
}

public struct ESEvent_screensharing_detach: Codable, Sendable {
    public let source_address_type: ESAddressType
    public let source_address: String?
    public let viewer_appleid: String?
    public let graphical_session_id: Int
}

public struct ESEvent_openssh_login: Codable, Sendable {
    public let success: Bool
    public let result_type: ESOpenSSHLoginResultType
    public let source_address_type: ESAddressType
    public let source_address: String
    public let username: String
    public let uid: Int? // collapsed by eslogger - should be public struct
}

public struct ESEvent_openssh_logout: Codable, Sendable {
    public let source_address_type: ESAddressType
    public let source_address: String
    public let username: String
    public let uid: Int
}

public struct ESEvent_login_login: Codable, Sendable {
    public let success: Bool
    public let failure_message: String?
    public let username: String
    public let uid: Int? // collapsed by eslogger - should be a public struct
}

public struct ESEvent_login_logout: Codable, Sendable {
    public let username: String
    public let uid: Int
}

public struct ESEvent_btm_launch_item_add: Codable, Sendable {
    public let instigator: ESProcess?
    public let app: ESProcess?
    public let item: ESBTMLaunchItem
    public let executable_path: String?
}

public struct ESEvent_btm_launch_item_remove: Codable, Sendable {
    public let instigator: ESProcess?
    public let app: ESProcess?
    public let item: ESBTMLaunchItem
}

public struct ESEvent_networkflow: Codable, Sendable {
    public let instigator: ESProcess
    public let remote_hostname: String?
    public let remote_address: String?
    public let remote_port: String?
    public let local_address: String?
    public let local_port: String?
    public let flow_protocol: ESIPProtocol
    public let flow_family: ESSocketDomain
    public let flow_type: ESSocketType
    public let direction: String
    public let url: String?
    public let uuid: String
}


public enum ESEvent: Codable, Sendable {
    case exec(ESEvent_exec)
    case fork(ESEvent_fork)
    case rename(ESEvent_rename)
    case open(ESEvent_open)
    case close(ESEvent_close)
    case create(ESEvent_create)
    case exchangedata(ESEvent_exchangedata)
    case exit(ESEvent_exit)
    case get_task(ESEvent_get_task)
    case kextload(ESEvent_kextload)
    case kextunload(ESEvent_kextunload)
    case link(ESEvent_link)
    case mmap(ESEvent_mmap)
    case mprotect(ESEvent_mprotect)
    case mount(ESEvent_mount)
    case unmount(ESEvent_unmount)
    case iokit_open(ESEvent_iokit_open)
    case setattrlist(ESEvent_setattrlist)
    case setextattr(ESEvent_setextattr)
    case setflags(ESEvent_setflags)
    case setmode(ESEvent_setmode)
    case setowner(ESEvent_setowner)
    case signal(ESEvent_signal)
    case unlink(ESEvent_unlink)
    case write(ESEvent_write)
    case file_provider_materialize(ESEvent_file_provider_materialize)
    case file_provider_update(ESEvent_file_provider_update)
    case readlink(ESEvent_readlink)
    case truncate(ESEvent_truncate)
    case lookup(ESEvent_lookup)
    case chdir(ESEvent_chdir)
    case getattrlist(ESEvent_getattrlist)
    case stat(ESEvent_stat)
    case access(ESEvent_access)
    case chroot(ESEvent_chroot)
    case utimes(ESEvent_utimes)
    case clone(ESEvent_clone)
    case fcntl(ESEvent_fcntl)
    case getextattr(ESEvent_getextattr)
    case listextattr(ESEvent_listextattr)
    case readdir(ESEvent_readdir)
    case deleteextattr(ESEvent_deleteextattr)
    case fsgetpath(ESEvent_fsgetpath)
    case dup(ESEvent_dup)
    case settime(ESEvent_settime)
    case uipc_bind(ESEvent_uipc_bind)
    case uipc_connect(ESEvent_uipc_connect)
    case setacl(ESEvent_setacl)
    case pty_grant(ESEvent_pty_grant)
    case pty_close(ESEvent_pty_close)
    case proc_check(ESEvent_proc_check)
    case searchfs(ESEvent_searchfs)
    case proc_suspend_resume(ESEvent_proc_suspend_resume)
    case cs_invalidated(ESEvent_cs_invalidated)
    case get_task_name(ESEvent_get_task_name)
    case trace(ESEvent_trace)
    case remote_thread_create(ESEvent_remote_thread_create)
    case remount(ESEvent_remount)
    case get_task_read(ESEvent_get_task_read)
    case get_task_inspect(ESEvent_get_task_inspect)
    case setuid(ESEvent_setuid)
    case setgid(ESEvent_setgid)
    case seteuid(ESEvent_seteuid)
    case setegid(ESEvent_setegid)
    case setreuid(ESEvent_setreuid)
    case setregid(ESEvent_setregid)
    case copyfile(ESEvent_copyfile)
    case authentication(ESEvent_authentication)
    case xp_malware_detected(ESEvent_xp_malware_detected)
    case xp_malware_remediated(ESEvent_xp_malware_remediated)
    case lw_session_login(ESEvent_lw_session_login)
    case lw_session_logout(ESEvent_lw_session_logout)
    case lw_session_lock(ESEvent_lw_session_lock)
    case lw_session_unlock(ESEvent_lw_session_unlock)
    case screensharing_attach(ESEvent_screensharing_attach)
    case screensharing_detach(ESEvent_screensharing_detach)
    case openssh_login(ESEvent_openssh_login)
    case openssh_logout(ESEvent_openssh_logout)
    case login_login(ESEvent_login_login)
    case login_logout(ESEvent_login_logout)
    case btm_launch_item_add(ESEvent_btm_launch_item_add)
    case btm_launch_item_remove(ESEvent_btm_launch_item_remove)
    case networkflow(ESEvent_networkflow)

    //
    // I believe (limited swift skillz) this is the only way to combat having a named key of "_0"
    // By default Codable wants {"exec":{"_0": {ESEvent_exec_kvs}}} but the
    // data from eslogger looks like {"exec":{ESEvent_exec_kvs}}
    //
    // https://forums.swift.org/t/se-0295-codable-synthesis-for-public-enums-with-associated-values/42408
    //
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch container.allKeys.first.unsafelyUnwrapped {
        case .exec:
            self = .exec(try container.decode(ESEvent_exec.self, forKey: ESEvent.CodingKeys.exec))
        case .fork:
            self = .fork(try container.decode(ESEvent_fork.self, forKey: ESEvent.CodingKeys.fork))
        case .rename:
            self = .rename(try container.decode(ESEvent_rename.self, forKey: ESEvent.CodingKeys.rename))
        case .open:
            self = .open(try container.decode(ESEvent_open.self, forKey: ESEvent.CodingKeys.open))
        case .close:
            self = .close(try container.decode(ESEvent_close.self, forKey: ESEvent.CodingKeys.close))
        case .create:
            self = .create(try container.decode(ESEvent_create.self, forKey: ESEvent.CodingKeys.create))
        case .exchangedata:
            self = .exchangedata(try container.decode(ESEvent_exchangedata.self, forKey: ESEvent.CodingKeys.exchangedata))
        case .exit:
            self = .exit(try container.decode(ESEvent_exit.self, forKey: ESEvent.CodingKeys.exit))
        case .get_task:
            self = .get_task(try container.decode(ESEvent_get_task.self, forKey: ESEvent.CodingKeys.get_task))
        case .kextload:
            self = .kextload(try container.decode(ESEvent_kextload.self, forKey: ESEvent.CodingKeys.kextload))
        case .kextunload:
            self = .kextunload(try container.decode(ESEvent_kextunload.self, forKey: ESEvent.CodingKeys.kextunload))
        case .link:
            self = .link(try container.decode(ESEvent_link.self, forKey: ESEvent.CodingKeys.link))
        case .mmap:
            self = .mmap(try container.decode(ESEvent_mmap.self, forKey: ESEvent.CodingKeys.mmap))
        case .mprotect:
            self = .mprotect(try container.decode(ESEvent_mprotect.self, forKey: ESEvent.CodingKeys.mprotect))
        case .mount:
            self = .mount(try container.decode(ESEvent_mount.self, forKey: ESEvent.CodingKeys.mount))
        case .unmount:
            self = .unmount(try container.decode(ESEvent_unmount.self, forKey: ESEvent.CodingKeys.unmount))
        case .iokit_open:
            self = .iokit_open(try container.decode(ESEvent_iokit_open.self, forKey: ESEvent.CodingKeys.iokit_open))
        case .setattrlist:
            self = .setattrlist(try container.decode(ESEvent_setattrlist.self, forKey: ESEvent.CodingKeys.setattrlist))
        case .setextattr:
            self = .setextattr(try container.decode(ESEvent_setextattr.self, forKey: ESEvent.CodingKeys.setextattr))
        case .setflags:
            self = .setflags(try container.decode(ESEvent_setflags.self, forKey: ESEvent.CodingKeys.setflags))
        case .setmode:
            self = .setmode(try container.decode(ESEvent_setmode.self, forKey: ESEvent.CodingKeys.setmode))
        case .setowner:
            self = .setowner(try container.decode(ESEvent_setowner.self, forKey: ESEvent.CodingKeys.setowner))
        case .signal:
            self = .signal(try container.decode(ESEvent_signal.self, forKey: ESEvent.CodingKeys.signal))
        case .unlink:
            self = .unlink(try container.decode(ESEvent_unlink.self, forKey: ESEvent.CodingKeys.unlink))
        case .write:
            self = .write(try container.decode(ESEvent_write.self, forKey: ESEvent.CodingKeys.write))
        case .file_provider_materialize:
            self = .file_provider_materialize(try container.decode(ESEvent_file_provider_materialize.self, forKey: ESEvent.CodingKeys.file_provider_materialize))
        case .file_provider_update:
            self = .file_provider_update(try container.decode(ESEvent_file_provider_update.self, forKey: ESEvent.CodingKeys.file_provider_update))
        case .readlink:
            self = .readlink(try container.decode(ESEvent_readlink.self, forKey: ESEvent.CodingKeys.readlink))
        case .truncate:
            self = .truncate(try container.decode(ESEvent_truncate.self, forKey: ESEvent.CodingKeys.truncate))
        case .lookup:
            self = .lookup(try container.decode(ESEvent_lookup.self, forKey: ESEvent.CodingKeys.lookup))
        case .chdir:
            self = .chdir(try container.decode(ESEvent_chdir.self, forKey: ESEvent.CodingKeys.chdir))
        case .getattrlist:
            self = .getattrlist(try container.decode(ESEvent_getattrlist.self, forKey: ESEvent.CodingKeys.getattrlist))
        case .stat:
            self = .stat(try container.decode(ESEvent_stat.self, forKey: ESEvent.CodingKeys.stat))
        case .access:
            self = .access(try container.decode(ESEvent_access.self, forKey: ESEvent.CodingKeys.access))
        case .chroot:
            self = .chroot(try container.decode(ESEvent_chroot.self, forKey: ESEvent.CodingKeys.chroot))
        case .utimes:
            self = .utimes(try container.decode(ESEvent_utimes.self, forKey: ESEvent.CodingKeys.utimes))
        case .clone:
            self = .clone(try container.decode(ESEvent_clone.self, forKey: ESEvent.CodingKeys.clone))
        case .fcntl:
            self = .fcntl(try container.decode(ESEvent_fcntl.self, forKey: ESEvent.CodingKeys.fcntl))
        case .getextattr:
            self = .getextattr(try container.decode(ESEvent_getextattr.self, forKey: ESEvent.CodingKeys.getextattr))
        case .listextattr:
            self = .listextattr(try container.decode(ESEvent_listextattr.self, forKey: ESEvent.CodingKeys.listextattr))
        case .readdir:
            self = .readdir(try container.decode(ESEvent_readdir.self, forKey: ESEvent.CodingKeys.readdir))
        case .deleteextattr:
            self = .deleteextattr(try container.decode(ESEvent_deleteextattr.self, forKey: ESEvent.CodingKeys.deleteextattr))
        case .fsgetpath:
            self = .fsgetpath(try container.decode(ESEvent_fsgetpath.self, forKey: ESEvent.CodingKeys.fsgetpath))
        case .dup:
            self = .dup(try container.decode(ESEvent_dup.self, forKey: ESEvent.CodingKeys.dup))
        case .settime:
            self = .settime(try container.decode(ESEvent_settime.self, forKey: ESEvent.CodingKeys.settime))
        case .uipc_bind:
            self = .uipc_bind(try container.decode(ESEvent_uipc_bind.self, forKey: ESEvent.CodingKeys.uipc_bind))
        case .uipc_connect:
            self = .uipc_connect(try container.decode(ESEvent_uipc_connect.self, forKey: ESEvent.CodingKeys.uipc_connect))
        case .setacl:
            self = .setacl(try container.decode(ESEvent_setacl.self, forKey: ESEvent.CodingKeys.setacl))
        case .pty_grant:
            self = .pty_grant(try container.decode(ESEvent_pty_grant.self, forKey: ESEvent.CodingKeys.pty_grant))
        case .pty_close:
            self = .pty_close(try container.decode(ESEvent_pty_close.self, forKey: ESEvent.CodingKeys.pty_close))
        case .proc_check:
            self = .proc_check(try container.decode(ESEvent_proc_check.self, forKey: ESEvent.CodingKeys.proc_check))
        case .searchfs:
            self = .searchfs(try container.decode(ESEvent_searchfs.self, forKey: ESEvent.CodingKeys.searchfs))
        case .proc_suspend_resume:
            self = .proc_suspend_resume(try container.decode(ESEvent_proc_suspend_resume.self, forKey: ESEvent.CodingKeys.proc_suspend_resume))
        case .cs_invalidated:
            self = .cs_invalidated(try container.decode(ESEvent_cs_invalidated.self, forKey: ESEvent.CodingKeys.cs_invalidated))
        case .get_task_name:
            self = .get_task_name(try container.decode(ESEvent_get_task_name.self, forKey: ESEvent.CodingKeys.get_task_name))
        case .trace:
            self = .trace(try container.decode(ESEvent_trace.self, forKey: ESEvent.CodingKeys.trace))
        case .remote_thread_create:
            self = .remote_thread_create(try container.decode(ESEvent_remote_thread_create.self, forKey: ESEvent.CodingKeys.remote_thread_create))
        case .remount:
            self = .remount(try container.decode(ESEvent_remount.self, forKey: ESEvent.CodingKeys.remount))
        case .get_task_read:
            self = .get_task_read(try container.decode(ESEvent_get_task_read.self, forKey: ESEvent.CodingKeys.get_task_read))
        case .get_task_inspect:
            self = .get_task_inspect(try container.decode(ESEvent_get_task_inspect.self, forKey: ESEvent.CodingKeys.get_task_inspect))
        case .setuid:
            self = .setuid(try container.decode(ESEvent_setuid.self, forKey: ESEvent.CodingKeys.setuid))
        case .setgid:
            self = .setgid(try container.decode(ESEvent_setgid.self, forKey: ESEvent.CodingKeys.setgid))
        case .seteuid:
            self = .seteuid(try container.decode(ESEvent_seteuid.self, forKey: ESEvent.CodingKeys.seteuid))
        case .setegid:
            self = .setegid(try container.decode(ESEvent_setegid.self, forKey: ESEvent.CodingKeys.setegid))
        case .setreuid:
            self = .setreuid(try container.decode(ESEvent_setreuid.self, forKey: ESEvent.CodingKeys.setreuid))
        case .setregid:
            self = .setregid(try container.decode(ESEvent_setregid.self, forKey: ESEvent.CodingKeys.setregid))
        case .copyfile:
            self = .copyfile(try container.decode(ESEvent_copyfile.self, forKey: ESEvent.CodingKeys.copyfile))
        case .authentication:
            self = .authentication(try container.decode(ESEvent_authentication.self, forKey: ESEvent.CodingKeys.authentication))
        case .xp_malware_detected:
            self = .xp_malware_detected(try container.decode(ESEvent_xp_malware_detected.self, forKey: ESEvent.CodingKeys.xp_malware_detected))
        case .xp_malware_remediated:
            self = .xp_malware_remediated(try container.decode(ESEvent_xp_malware_remediated.self, forKey: ESEvent.CodingKeys.xp_malware_remediated))
        case .lw_session_login:
            self = .lw_session_login(try container.decode(ESEvent_lw_session_login.self, forKey: ESEvent.CodingKeys.lw_session_login))
        case .lw_session_logout:
            self = .lw_session_logout(try container.decode(ESEvent_lw_session_logout.self, forKey: ESEvent.CodingKeys.lw_session_logout))
        case .lw_session_lock:
            self = .lw_session_lock(try container.decode(ESEvent_lw_session_lock.self, forKey: ESEvent.CodingKeys.lw_session_lock))
        case .lw_session_unlock:
            self = .lw_session_unlock(try container.decode(ESEvent_lw_session_unlock.self, forKey: ESEvent.CodingKeys.lw_session_unlock))
        case .screensharing_attach:
            self = .screensharing_attach(try container.decode(ESEvent_screensharing_attach.self, forKey: ESEvent.CodingKeys.screensharing_attach))
        case .screensharing_detach:
            self = .screensharing_detach(try container.decode(ESEvent_screensharing_detach.self, forKey: ESEvent.CodingKeys.screensharing_detach))
        case .openssh_login:
            self = .openssh_login(try container.decode(ESEvent_openssh_login.self, forKey: ESEvent.CodingKeys.openssh_login))
        case .openssh_logout:
            self = .openssh_logout(try container.decode(ESEvent_openssh_logout.self, forKey: ESEvent.CodingKeys.openssh_logout))
        case .login_login:
            self = .login_login(try container.decode(ESEvent_login_login.self, forKey: ESEvent.CodingKeys.login_login))
        case .login_logout:
            self = .login_logout(try container.decode(ESEvent_login_logout.self, forKey: ESEvent.CodingKeys.login_logout))
        case .btm_launch_item_add:
            self = .btm_launch_item_add(try container.decode(ESEvent_btm_launch_item_add.self, forKey: ESEvent.CodingKeys.btm_launch_item_add))
        case .btm_launch_item_remove:
            self = .btm_launch_item_remove(try container.decode(ESEvent_btm_launch_item_remove.self, forKey: ESEvent.CodingKeys.btm_launch_item_remove))
        case .networkflow:
            self = .networkflow(try container.decode(ESEvent_networkflow.self, forKey: ESEvent.CodingKeys.networkflow))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .exec(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.exec)
        case .fork(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.fork)
        case .rename(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.rename)
        case .open(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.open)
        case .close(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.close)
        case .create(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.create)
        case .exchangedata(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.exchangedata)
        case .exit(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.exit)
        case .get_task(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.get_task)
        case .kextload(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.kextload)
        case .kextunload(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.kextunload)
        case .link(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.link)
        case .mmap(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.mmap)
        case .mprotect(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.mprotect)
        case .mount(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.mount)
        case .unmount(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.unmount)
        case .iokit_open(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.iokit_open)
        case .setattrlist(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setattrlist)
        case .setextattr(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setextattr)
        case .setflags(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setflags)
        case .setmode(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setmode)
        case .setowner(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setowner)
        case .signal(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.signal)
        case .unlink(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.unlink)
        case .write(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.write)
        case .file_provider_materialize(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.file_provider_materialize)
        case .file_provider_update(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.file_provider_update)
        case .readlink(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.readlink)
        case .truncate(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.truncate)
        case .lookup(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.lookup)
        case .chdir(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.chdir)
        case .getattrlist(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.getattrlist)
        case .stat(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.stat)
        case .access(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.access)
        case .chroot(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.chroot)
        case .utimes(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.utimes)
        case .clone(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.clone)
        case .fcntl(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.fcntl)
        case .getextattr(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.getextattr)
        case .listextattr(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.listextattr)
        case .readdir(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.readdir)
        case .deleteextattr(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.deleteextattr)
        case .fsgetpath(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.fsgetpath)
        case .dup(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.dup)
        case .settime(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.settime)
        case .uipc_bind(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.uipc_bind)
        case .uipc_connect(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.uipc_connect)
        case .setacl(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setacl)
        case .pty_grant(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.pty_grant)
        case .pty_close(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.pty_close)
        case .proc_check(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.proc_check)
        case .searchfs(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.searchfs)
        case .proc_suspend_resume(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.proc_suspend_resume)
        case .cs_invalidated(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.cs_invalidated)
        case .get_task_name(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.get_task_name)
        case .trace(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.trace)
        case .remote_thread_create(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.remote_thread_create)
        case .remount(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.remount)
        case .get_task_read(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.get_task_read)
        case .get_task_inspect(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.get_task_inspect)
        case .setuid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setuid)
        case .setgid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setgid)
        case .seteuid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.seteuid)
        case .setegid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setegid)
        case .setreuid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setreuid)
        case .setregid(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.setregid)
        case .copyfile(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.copyfile)
        case .authentication(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.authentication)
        case .xp_malware_detected(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.xp_malware_detected)
        case .xp_malware_remediated(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.xp_malware_remediated)
        case .lw_session_login(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.lw_session_login)
        case .lw_session_logout(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.lw_session_logout)
        case .lw_session_lock(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.lw_session_lock)
        case .lw_session_unlock(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.lw_session_unlock)
        case .screensharing_attach(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.screensharing_attach)
        case .screensharing_detach(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.screensharing_detach)
        case .openssh_login(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.openssh_login)
        case .openssh_logout(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.openssh_logout)
        case .login_login(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.login_login)
        case .login_logout(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.login_logout)
        case .btm_launch_item_add(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.btm_launch_item_add)
        case .btm_launch_item_remove(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.btm_launch_item_remove)
        case .networkflow(let evt):
            try container.encode(evt, forKey: ESEvent.CodingKeys.networkflow)
        }
    }
    
    enum CodingKeys: String, CodingKey {
        case  open, exec, fork, rename, close, create, exchangedata, exit, get_task, kextload,
              kextunload, link, mmap, mprotect, mount, unmount, iokit_open, setattrlist, setextattr,
              setflags, setmode, setowner, signal, unlink, write, file_provider_materialize,
              file_provider_update, readlink, truncate, lookup, chdir, getattrlist, stat, access,
              chroot, utimes, clone, fcntl, getextattr, listextattr, readdir, deleteextattr, fsgetpath,
              dup, settime, uipc_bind, uipc_connect, setacl, pty_grant, pty_close, proc_check, searchfs,
              proc_suspend_resume, cs_invalidated, get_task_name, trace, remote_thread_create, remount,
              get_task_read, get_task_inspect, setuid, setgid, seteuid, setegid, setreuid, setregid,
              copyfile, authentication, xp_malware_detected, xp_malware_remediated, lw_session_login,
              lw_session_logout, lw_session_lock, lw_session_unlock, screensharing_attach, screensharing_detach,
              openssh_login, openssh_logout, login_login, login_logout, btm_launch_item_add, btm_launch_item_remove,
              networkflow
    }
}


public enum EventType: Int, Codable, CaseIterable, Sendable {
    case ES_EVENT_TYPE_AUTH_EXEC=0
    , ES_EVENT_TYPE_AUTH_OPEN
    , ES_EVENT_TYPE_AUTH_KEXTLOAD
    , ES_EVENT_TYPE_AUTH_MMAP
    , ES_EVENT_TYPE_AUTH_MPROTECT
    , ES_EVENT_TYPE_AUTH_MOUNT
    , ES_EVENT_TYPE_AUTH_RENAME
    , ES_EVENT_TYPE_AUTH_SIGNAL
    , ES_EVENT_TYPE_AUTH_UNLINK
    , ES_EVENT_TYPE_NOTIFY_EXEC
    , ES_EVENT_TYPE_NOTIFY_OPEN
    , ES_EVENT_TYPE_NOTIFY_FORK
    , ES_EVENT_TYPE_NOTIFY_CLOSE
    , ES_EVENT_TYPE_NOTIFY_CREATE
    , ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
    , ES_EVENT_TYPE_NOTIFY_EXIT
    , ES_EVENT_TYPE_NOTIFY_GET_TASK
    , ES_EVENT_TYPE_NOTIFY_KEXTLOAD
    , ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD
    , ES_EVENT_TYPE_NOTIFY_LINK
    , ES_EVENT_TYPE_NOTIFY_MMAP
    , ES_EVENT_TYPE_NOTIFY_MPROTECT
    , ES_EVENT_TYPE_NOTIFY_MOUNT
    , ES_EVENT_TYPE_NOTIFY_UNMOUNT
    , ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN
    , ES_EVENT_TYPE_NOTIFY_RENAME
    , ES_EVENT_TYPE_NOTIFY_SETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_SETEXTATTR
    , ES_EVENT_TYPE_NOTIFY_SETFLAGS
    , ES_EVENT_TYPE_NOTIFY_SETMODE
    , ES_EVENT_TYPE_NOTIFY_SETOWNER
    , ES_EVENT_TYPE_NOTIFY_SIGNAL
    , ES_EVENT_TYPE_NOTIFY_UNLINK
    , ES_EVENT_TYPE_NOTIFY_WRITE
    , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
    , ES_EVENT_TYPE_AUTH_READLINK
    , ES_EVENT_TYPE_NOTIFY_READLINK
    , ES_EVENT_TYPE_AUTH_TRUNCATE
    , ES_EVENT_TYPE_NOTIFY_TRUNCATE
    , ES_EVENT_TYPE_AUTH_LINK
    , ES_EVENT_TYPE_NOTIFY_LOOKUP
    , ES_EVENT_TYPE_AUTH_CREATE
    , ES_EVENT_TYPE_AUTH_SETATTRLIST
    , ES_EVENT_TYPE_AUTH_SETEXTATTR
    , ES_EVENT_TYPE_AUTH_SETFLAGS
    , ES_EVENT_TYPE_AUTH_SETMODE
    , ES_EVENT_TYPE_AUTH_SETOWNER
    , ES_EVENT_TYPE_AUTH_CHDIR
    , ES_EVENT_TYPE_NOTIFY_CHDIR
    , ES_EVENT_TYPE_AUTH_GETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_GETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_STAT
    , ES_EVENT_TYPE_NOTIFY_ACCESS
    , ES_EVENT_TYPE_AUTH_CHROOT
    , ES_EVENT_TYPE_NOTIFY_CHROOT
    , ES_EVENT_TYPE_AUTH_UTIMES
    , ES_EVENT_TYPE_NOTIFY_UTIMES
    , ES_EVENT_TYPE_AUTH_CLONE
    , ES_EVENT_TYPE_NOTIFY_CLONE
    , ES_EVENT_TYPE_NOTIFY_FCNTL
    , ES_EVENT_TYPE_AUTH_GETEXTATTR
    , ES_EVENT_TYPE_NOTIFY_GETEXTATTR
    , ES_EVENT_TYPE_AUTH_LISTEXTATTR
    , ES_EVENT_TYPE_NOTIFY_LISTEXTATTR
    , ES_EVENT_TYPE_AUTH_READDIR
    , ES_EVENT_TYPE_NOTIFY_READDIR
    , ES_EVENT_TYPE_AUTH_DELETEEXTATTR
    , ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
    , ES_EVENT_TYPE_AUTH_FSGETPATH
    , ES_EVENT_TYPE_NOTIFY_FSGETPATH
    , ES_EVENT_TYPE_NOTIFY_DUP
    , ES_EVENT_TYPE_AUTH_SETTIME
    , ES_EVENT_TYPE_NOTIFY_SETTIME
    , ES_EVENT_TYPE_NOTIFY_UIPC_BIND
    , ES_EVENT_TYPE_AUTH_UIPC_BIND
    , ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT
    , ES_EVENT_TYPE_AUTH_UIPC_CONNECT
    , ES_EVENT_TYPE_AUTH_EXCHANGEDATA
    , ES_EVENT_TYPE_AUTH_SETACL
    , ES_EVENT_TYPE_NOTIFY_SETACL
    , ES_EVENT_TYPE_NOTIFY_PTY_GRANT
    , ES_EVENT_TYPE_NOTIFY_PTY_CLOSE
    , ES_EVENT_TYPE_AUTH_PROC_CHECK
    , ES_EVENT_TYPE_NOTIFY_PROC_CHECK
    , ES_EVENT_TYPE_AUTH_GET_TASK
    , ES_EVENT_TYPE_AUTH_SEARCHFS
    , ES_EVENT_TYPE_NOTIFY_SEARCHFS
    , ES_EVENT_TYPE_AUTH_FCNTL
    , ES_EVENT_TYPE_AUTH_IOKIT_OPEN
    , ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME
    , ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME
    , ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME
    , ES_EVENT_TYPE_NOTIFY_TRACE
    , ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
    , ES_EVENT_TYPE_AUTH_REMOUNT
    , ES_EVENT_TYPE_NOTIFY_REMOUNT
    , ES_EVENT_TYPE_AUTH_GET_TASK_READ
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_READ
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT
    , ES_EVENT_TYPE_NOTIFY_SETUID
    , ES_EVENT_TYPE_NOTIFY_SETGID
    , ES_EVENT_TYPE_NOTIFY_SETEUID
    , ES_EVENT_TYPE_NOTIFY_SETEGID
    , ES_EVENT_TYPE_NOTIFY_SETREUID
    , ES_EVENT_TYPE_NOTIFY_SETREGID
    , ES_EVENT_TYPE_AUTH_COPYFILE
    , ES_EVENT_TYPE_NOTIFY_COPYFILE
    , ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
    , ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
    , ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
    , ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
    , ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
    , ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
    , ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
    , ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    , ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
    , ES_EVENT_TYPE_LAST
    , ES_EVENT_TYPE_NOTIFY_NETWORKFLOW=90210 // nubco added type to support Network Extension data
    
    public func shortName() -> String {
        return String(describing: self).lowercased().components(separatedBy: ["_",])[4...].joined(separator: "_")
    }
}
