

/*----------------------------------------------------------------------
    INCLUDE FILES
----------------------------------------------------------------------*/
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/irqnr.h>
#include <linux/tick.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/list.h>
#include <linux/fcntl.h>
#include <linux/syscalls.h>
#include <linux/delay.h>

/*----------------------------------------------------------------------
    MACROS
----------------------------------------------------------------------*/
#define IOSTAT_TIMER_S 2 //stat io one time every IOSTAT_TIMER_S seconds
#define IOSTAT_PID_HASH_LEN 1000 //hash list lenght
#define IOSTAT_PID_SUM 2000 //hash list lenght
#define IOSTAT_PID_IN_LINE 5 //output pids in one msg line
#define IOSTAT_TOP_LIMIT 200 //sum of output pids
#define IOSTAT_TOP_PROCESS_THRESHOLD 3 //threshold of one task io r/w stat (MB)
#define IOSTAT_TOP_DISK_THRESHOLD 20 //threshold of disk io r/w stat (MB)
#define IOSTAT_IOWAIT_THRESHOLD 5 //threshold of iowait (n%)
#define IOSTAT_COMMANDLEN 16 //pid name lenght
#define IOSTAT_BUFLEN 512 //io buffer len
#define IOSTAT_DEVSTAT_PATH "/sys/block/mmcblk0/stat"

//indicate the io node is valid or invalid
#define IOSTAT_NODE_VALID 1
#define IOSTAT_NODE_INVALID 0

#define BTOKB(n) ((n)>>10)
#define BTOMB(n) ((n)>>20)
#define KBTOMB(n) ((n)>>10)
#define SECTOKB(n) ((n)>>1)

/*----------------------------------------------------------------------
    LOCAL TYPE
----------------------------------------------------------------------*/
//io information stat for one Process
struct io_node
{
    int valid; //the value indicate whether the node is using or the pid have killed
    int pid;   //process pid
    u64 rchar; //bytes read
    u64 wchar; //bytes written
    u64 syscr; //read syscalls
    u64 syscw; //write syscalls
    u64 read_bytes;  //The number of bytes which this task has caused to be read from storage.
    u64 write_bytes; //The number of bytes which this task has caused, or shall cause to be written to disk.
    u64 cwrite_bytes;//cancelled write bytes by truncates some dirty pagecache
    char command[IOSTAT_COMMANDLEN + 4]; //pid name "[pid]/comm"
    struct hlist_node node; //current node in hash list
    struct hlist_node hlist;//current node in all list
};

//io information stat for device
struct io_diskstats
{
    unsigned long read_tps;     //total number of reads completed successfully
    unsigned long read_merged;  //number of reads merged
    unsigned long read_sectors; //number of sectors read. This is the total number of sectors read successfully.
    unsigned long read_time_ms; //number of milliseconds spent reading
    unsigned long write_tps;    //total number of writes completed successfully.
    unsigned long write_merged; //number of writes merged
    unsigned long write_sectors;//number of sectors written. This is the total number of sectors written successfully.
    unsigned long write_time_ms;//number of milliseconds spent writing
    unsigned long io_current;   //number of I/Os currently in progress.
    unsigned long time_ms_io;   //number of milliseconds spent doing I/Os (ms).
    unsigned long time_weight;  //weighted time spent doing I/Os (ms).
};

//cpu information stat
struct io_cpustat
{
    u64 user;
    u64 nice;
    u64 system;
    u64 softirq;
    u64 irq;
    u64 idle;
    u64 iowait;
};

//"io_output_**": storage the output information.
struct io_output_node
{
    u32 read_KB;
    u32 write_KB;
    struct io_node *ion;
};

struct io_output_info
{
    unsigned long read_KB;  //read(KB)
    unsigned long write_KB; //write(KB)
    unsigned long iotps;    //read and write tps
    unsigned long iotime_ms;//spent doing I/Os (ms).
    unsigned long iowait;   //cpu io wait ratio
    unsigned long iotop_cnt;//top n process
    struct io_output_node iotop[IOSTAT_TOP_LIMIT];//process's io information
};

/*----------------------------------------------------------------------
    GLOBAL VARIABLES
----------------------------------------------------------------------*/
//workqueue variables
static struct delayed_work stat_io_work;
static struct workqueue_struct *workqueue_stat_io;

//io stat variables
static struct hlist_head *io_pid_hash = NULL; //hash list for save all process by pid number
static struct hlist_head io_pid_all; //one list that contain all the pid.
static struct io_output_info io_inf = {0}; //io information will output to kmsg
static bool ioinfo_enabled = true; //proc request flag

/*----------------------------------------------------------------------
    FUNCTION DEFINITIONS
----------------------------------------------------------------------*/
/**
*   @brief:    Alloc new io node for current pid, and completes initialization.
*   @param: void
*   @return: the alloced new io_node, or NULL
*/
static struct io_node *io_top_new_ionode(void)
{
    struct io_node *ion = NULL;

    ion = (struct io_node *)kzalloc(sizeof(struct io_node), GFP_KERNEL);
    if (ion)
    {
        INIT_HLIST_NODE(&ion->node);
        INIT_HLIST_NODE(&ion->hlist);
    }

    return ion;
}

/**
*   @brief:    Find the io node by process's pid and name from hash list.
*   @param: pid: the pid of current Process
*   @param: comm: the name of current Process
*   @return: the found io_node, or NULL when not found.
*/
static struct io_node *io_top_get_ionode(int pid, char *comm)
{
    struct io_node *ion = NULL;
    struct hlist_head *phead;

    if (NULL == comm)
    {
        return NULL;
    }

    phead = &io_pid_hash[pid % IOSTAT_PID_HASH_LEN];
    hlist_for_each_entry(ion, phead, node)
    {
        if ((ion->pid == pid) && (0 == strncmp(ion->command, comm, IOSTAT_COMMANDLEN)))
        {
            break;
        }
    }

    return ion;
}

/**
*   @brief:    Add new io node to hash list.
*   @param: ion: new io node data
*   @return: void
*/
static void io_top_add_ionode(struct io_node *ion)
{
    struct hlist_head *phead;

    if (NULL == ion)
    {
        return;
    }

    phead = &io_pid_hash[ion->pid % IOSTAT_PID_HASH_LEN];
    hlist_add_head(&ion->node, phead);
    hlist_add_head(&ion->hlist, &io_pid_all);
    return;
}

/**
*   @brief:    Update the new data to old io node
*   @param: old_ion: old io node which will update
*   @param: new_ion: new io node data
*   @return: void
*/
static void io_top_set_ionode(struct io_node *old_ion, struct io_node *new_ion)
{
    if ((NULL == old_ion) || (NULL == new_ion))
    {
        return;
    }

    old_ion->rchar = new_ion->rchar;
    old_ion->wchar = new_ion->wchar;
    old_ion->syscr = new_ion->syscr;
    old_ion->syscw = new_ion->syscw;
    old_ion->read_bytes = new_ion->read_bytes;
    old_ion->write_bytes = new_ion->write_bytes;
    old_ion->cwrite_bytes = new_ion->cwrite_bytes;
    return;
}

/**
*   @brief:    Set all io node to invalid status when io top stat begin.
*   @param: void
*   @return: void
*/
static void io_top_set_all_to_invalid(void)
{
    struct io_node *ion = NULL;

    hlist_for_each_entry(ion, &io_pid_all, hlist)
    {
        ion->valid = IOSTAT_NODE_INVALID;
    }
    return;
}

/**
*   @brief:    Set one io node to valid, mean the node is useful
*   @param: ion: io node
*   @return: void
*/
static void io_top_set_node_to_valid(struct io_node *ion)
{
    if (ion)
    {
        ion->valid = IOSTAT_NODE_VALID;
    }
    return;
}

/**
*   @brief:    Delete invalid io node. Some io node will be invalid when some process have been killed,
*                  so scan all io node in the node list and delete invalid node when io top stat have finished.
*   @param: void
*   @return: void
*/
static void io_top_del_invalid_ionode(void)
{
    struct io_node *ion = NULL;
    struct hlist_node *temp;

    hlist_for_each_entry_safe(ion, temp, &io_pid_all, hlist)
    {
        if (IOSTAT_NODE_INVALID == ion->valid)
        {
            hlist_del(&ion->node); //delete in hash list
            hlist_del(&ion->hlist);//delete in all node list
            kfree(ion);
        }
    }
    return;
}

/**
*   @brief:    save io information to output container
*   @param: pio_inf: output container
*   @param: ion: current io node
*   @param: read_bytes: increased read bytes
*   @param: write_bytes: increased write bytes
*   @return: void
*/
static void io_top_save_io_info(struct io_output_info *pio_inf,
                                struct io_node *ion, u64 read_bytes, u64 write_bytes)
{
    if (pio_inf && ion && (pio_inf->iotop_cnt < IOSTAT_TOP_LIMIT))
    {
        pio_inf->iotop[pio_inf->iotop_cnt].read_KB = (u32)BTOKB(read_bytes);
        pio_inf->iotop[pio_inf->iotop_cnt].write_KB = (u32)BTOKB(write_bytes);
        pio_inf->iotop[pio_inf->iotop_cnt].ion = ion;
        pio_inf->iotop_cnt++;
    }
    else
    {
        pr_err("io_stat:ERR: iotop task more than %d.\n", IOSTAT_TOP_LIMIT);
    }
    return;
}

/**
*   @brief:    Get current tast io information.
*   @param: task: task_struct data of current pid
*   @param: ion: io node that save the task io information
*   @param: whole: get io data of all threads that belong to current process
*   @return: whether sucess or fail. 0:sucess, other is fail.
*/
static int io_top_get_tast_io(struct task_struct *task, struct io_node *ion, int whole)
{
    struct task_io_accounting acct = task->ioac;
    unsigned long flags;
    int ret = -EINVAL;

    if ((NULL == task) || (NULL == ion))
    {
        return ret;
    }

    ret = mutex_lock_killable(&task->signal->cred_guard_mutex);
    if (ret)
    {
        pr_debug("io_stat:ERR: iotop mutex lock killable failed!\n");
        return ret;
    }

    if (whole && lock_task_sighand(task, &flags))
    {
        struct task_struct *t = task;

        task_io_accounting_add(&acct, &task->signal->ioac);
        while_each_thread(task, t)
        task_io_accounting_add(&acct, &t->ioac);
        unlock_task_sighand(task, &flags);
    }

    ion->rchar = acct.rchar;
    ion->wchar = acct.wchar;
    ion->syscr = acct.syscr;
    ion->syscw = acct.syscw;
    ion->read_bytes = acct.read_bytes;
    ion->write_bytes = acct.write_bytes;
    ion->cwrite_bytes = acct.cancelled_write_bytes;

    mutex_unlock(&task->signal->cred_guard_mutex);

    return ret;
}

/**
*   @brief:    Convert the pid to task, then get task io information.
*   @param: pid_nr: current pid number.
*   @param: ion: io node that save the task io information
*   @return: whether sucess or fail. 0:sucess, other is fail.
*/
static int io_top_io_accounting(int pid_nr, struct io_node *ion)
{
    struct pid *pid = NULL;
    struct task_struct *task = NULL;
    int ret = -EINVAL;

    if (NULL == ion)
    {
        return ret;
    }

    ion->pid = pid_nr;

    pid = find_get_pid(pid_nr);
    if (NULL == pid)
    {
        return ret;
    }

    task = get_pid_task(pid, PIDTYPE_PID);
    if (task)
    {
        int whole = thread_group_leader(task) ? 1 : 0;

        strncpy(ion->command, task->comm, IOSTAT_COMMANDLEN);
        ret = io_top_get_tast_io(task, ion, whole);
        if (0 != ret)
        {
            pr_debug("io_stat:ERR: iotop do io accounting failed!\n");
        }
        put_task_struct(task);
    }

    put_pid(pid);
    return ret;
}


/**
*   @brief:    Stat current pid io information.
*   @pid_nr: pid number
*   @param: pio_inf: the output container to storage some pid's io information
*   @return: void
*/
static void io_top_stat_one_task(int pid_nr, struct io_output_info *pio_inf)
{
    struct io_node ion_loc = {0};
    struct io_node *new_ion = NULL;
    struct io_node *old_ion = NULL;
    u64 rchar = 0;
    u64 wchar = 0;
    u64 syscr = 0;
    u64 syscw = 0;
    u64 read_bytes = 0;
    u64 write_bytes = 0;
    u64 cwrite_bytes = 0;

    if (NULL == pio_inf)
    {
        return;
    }

    //Get new io information for this pid.
    if (0 != io_top_io_accounting(pid_nr, &ion_loc))
    {
        return;
    }

    //if the task no io operate on the storage, ignore it
    if ((0 == ion_loc.read_bytes) && (0 == ion_loc.write_bytes))
    {
        return;
    }

    //Get old io node from hash list, then compare with new io node
    //1.Add the new node to hash list when not have old node
    //2.Update the old node information when the new node have increased r/w
    old_ion = io_top_get_ionode(ion_loc.pid, ion_loc.command);
    if (NULL == old_ion)
    {
        //Alloc new io node for this pid.
        new_ion = io_top_new_ionode();
        if (NULL == new_ion)
        {
            pr_info("io_stat:ERR: io_node memory alloc failed.\n");
            return;
        }
        *new_ion = ion_loc;
        io_top_add_ionode(new_ion);

        read_bytes = new_ion->read_bytes;
        write_bytes = new_ion->write_bytes;
    }
    else
    {
        new_ion = &ion_loc;
        rchar = new_ion->rchar - old_ion->rchar;
        wchar = new_ion->wchar - old_ion->wchar;
        syscr = new_ion->syscr - old_ion->syscr;
        syscw = new_ion->syscw - old_ion->syscw;
        read_bytes = new_ion->read_bytes - old_ion->read_bytes;
        write_bytes = new_ion->write_bytes - old_ion->write_bytes;
        cwrite_bytes = new_ion->cwrite_bytes - old_ion->cwrite_bytes;

        if (rchar || wchar || syscr || syscw || read_bytes || write_bytes || cwrite_bytes)
        {
            io_top_set_ionode(old_ion, new_ion);
        }
        new_ion = old_ion;
    }

    //Set one io node to valid, mean the node is useful
    io_top_set_node_to_valid(new_ion);

    //save rw io information that will to be output
    if (BTOMB(read_bytes + write_bytes) > IOSTAT_TOP_PROCESS_THRESHOLD)
    {
        io_top_save_io_info(pio_inf, new_ion, read_bytes, write_bytes);
    }
    return;
}

/**
*   @brief:    Stat all pid io information that include read and write .
*   @param: pio_inf: the output container to storage some pid's io information
*   @return: void
*   @note: main function of io top stat
*/
static void io_top_stat(struct io_output_info *pio_inf)
{
    struct task_struct *task = NULL;
    int *pids = NULL;
    u32 pid_cnt = 0;
    u32 i = 0;

    if (NULL == pio_inf)
    {
        return;
    }

    pio_inf->iotop_cnt = 0;
    pids = (int *)kzalloc(IOSTAT_PID_SUM * sizeof(int), GFP_KERNEL);
    if (NULL == pids)
    {
        pr_err("io_stat:ERR: alloc memory failed!\n");
        return;
    }

    //set all old io node to invalid
    io_top_set_all_to_invalid();

    //search all task, then get task's io information
    read_lock(&tasklist_lock);
    for_each_process(task)
    {
        pids[pid_cnt++] = task->pid;
        if (IOSTAT_PID_SUM == pid_cnt)
        {
            break;
        }
    }
    read_unlock(&tasklist_lock);

    for (i = 0; i < pid_cnt; i++)
    {
        io_top_stat_one_task(pids[i], pio_inf);
    }

    //delete invalid pid node that the task have been killed.
    io_top_del_invalid_ionode();
    kfree(pids);
    return;
}


/**
*   @brief:    Get disk io information and save to io_diskstats
*   @param: pio_d: disk io container
*   @return: read bytes > 0: sucess; others: fail.
*/
static int io_dev_get_devstats(struct io_diskstats *pio_d)
{
    int ret = -EINVAL;
    struct file *filp = NULL;
    char buf[IOSTAT_BUFLEN] = {0};

    if (NULL == pio_d)
    {
        return ret;
    }

    /* ignore given mode and open file as read-only */
    filp = filp_open(IOSTAT_DEVSTAT_PATH, O_RDONLY, 0);
    if (IS_ERR(filp))
    {
        pr_err("io_stat:ERR: open %s failed, ret:%lu\n", IOSTAT_DEVSTAT_PATH, (unsigned long)filp);
        return ret;
    }

    ret = kernel_read(filp, 0, buf, IOSTAT_BUFLEN);
    if (ret > 0)
    {
        sscanf(buf, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", \
               &pio_d->read_tps,
               &pio_d->read_merged,
               &pio_d->read_sectors,
               &pio_d->read_time_ms,
               &pio_d->write_tps,
               &pio_d->write_merged,
               &pio_d->write_sectors,
               &pio_d->write_time_ms,
               &pio_d->io_current,
               &pio_d->time_ms_io,
               &pio_d->time_weight);
    }

    filp_close(filp, NULL);
    return ret;
}

/**
*   @brief:    Get disk io information and save to io_output_info
*   @param: pio_inf: the output container to storage disk io information
*   @return: void
*   @note: main function of device'io stat, only stat the increased io throughput
*/
static void io_dev_stat(struct io_output_info *pio_inf)
{
    static struct io_diskstats io_old_d = {0};
    struct io_diskstats io_new_d = {0};

    if (NULL == pio_inf)
    {
        return;
    }

    if (io_dev_get_devstats(&io_new_d) <= 0)
    {
        return;
    }

    //compare new diskstats with old diskstats, get increased io
    pio_inf->read_KB   = SECTOKB(io_new_d.read_sectors - io_old_d.read_sectors);
    pio_inf->write_KB  = SECTOKB(io_new_d.write_sectors - io_old_d.write_sectors);
    pio_inf->iotps     = (io_new_d.read_tps - io_old_d.read_tps) + \
                         (io_new_d.write_tps - io_old_d.write_tps);
    pio_inf->iotime_ms = io_new_d.time_ms_io - io_old_d.time_ms_io;

    io_old_d = io_new_d;
    return;
}


/**
*   @brief:    get cpu idle time or iowait time.
*   @param: cpu: current cpu id
*   @return:
*/
#ifdef arch_idle_time
static cputime64_t get_idle_time(int cpu)
{
    cputime64_t idle;

    idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
    if (cpu_online(cpu) && !nr_iowait_cpu(cpu))
    {
        idle += arch_idle_time(cpu);
    }
    return idle;
}

static cputime64_t get_iowait_time(int cpu)
{
    cputime64_t iowait;

    iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
    if (cpu_online(cpu) && nr_iowait_cpu(cpu))
    {
        iowait += arch_idle_time(cpu);
    }
    return iowait;
}

#else
static u64 get_idle_time(int cpu)
{
    u64 idle, idle_time = -1ULL;

    if (cpu_online(cpu))
    {
        idle_time = get_cpu_idle_time_us(cpu, NULL);
    }

    /* !NO_HZ or cpu offline so we can rely on cpustat.idle */
    if (idle_time == -1ULL)
    {
        idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
    }
    else
    {
        idle = usecs_to_cputime64(idle_time);
    }
    return idle;
}

static u64 get_iowait_time(int cpu)
{
    u64 iowait, iowait_time = -1ULL;

    if (cpu_online(cpu))
    {
        iowait_time = get_cpu_iowait_time_us(cpu, NULL);
    }

    /* !NO_HZ or cpu offline so we can rely on cpustat.iowait */
    if (iowait_time == -1ULL)

    {
        iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
    }
    else
    {
        iowait = usecs_to_cputime64(iowait_time);
    }
    return iowait;
}
#endif

/**
*   @brief:    stat all cpu run information
*   @param: pio_c: the container to storage cpu information
*   @return: void
*/
static void io_wait_get_cpustat(struct io_cpustat *pio_c)
{
    int i = 0;

    if (NULL == pio_c)
    {
        return;
    }

    memset(pio_c, 0, sizeof(struct io_cpustat));
    for_each_possible_cpu(i)
    {
        pio_c->user     += kcpustat_cpu(i).cpustat[CPUTIME_USER];
        pio_c->nice     += kcpustat_cpu(i).cpustat[CPUTIME_NICE];
        pio_c->system   += kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
        pio_c->softirq  += kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
        pio_c->irq      += kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
        pio_c->idle     += get_idle_time(i);
        pio_c->iowait   += get_iowait_time(i);
    }
    return;
}

/**
*   @brief:    stat all cpu run information, and then compute the value of iowait
*   @param: pio_inf: the output container to storage cpu information
*   @return: void
*   @note: main function of iowait stat
*/
static void io_wait_stat(struct io_output_info *pio_inf)
{
    static struct io_cpustat io_old_cpu = {0};
    struct io_cpustat io_new_cpu = {0};
    struct io_cpustat inc = {0};// increased cpu stat

    if (NULL == pio_inf)
    {
        return;
    }

    io_wait_get_cpustat(&io_new_cpu);

    //compare new cpustat with old cpustat, get increased data
    inc.user    = io_new_cpu.user - io_old_cpu.user;
    inc.nice    = io_new_cpu.nice - io_old_cpu.nice;
    inc.system  = io_new_cpu.system - io_old_cpu.system;
    inc.softirq = io_new_cpu.softirq - io_old_cpu.softirq;
    inc.irq     = io_new_cpu.irq - io_old_cpu.irq;
    inc.idle    = io_new_cpu.idle - io_old_cpu.idle;
    inc.iowait  = io_new_cpu.iowait - io_old_cpu.iowait;

    // compute the ratio of iowait
    pio_inf->iowait = (u32)(inc.iowait * 100 / (inc.user + inc.nice + inc.system +
                            inc.softirq + inc.irq + inc.idle + inc.iowait));
    io_old_cpu = io_new_cpu;
    return;
}

/**
*   @brief:    output all the io stat message to kmsg log
*   @param: pio_inf: the output container to storage all io information
*   @return: void
*   @note: pio_inf contains "iotop", "iodisk", and "iowait".
*/
static void io_info_output_msg(struct io_output_info *pio_inf)
{
    int i = 0;
    int len = 0;
    char buf[IOSTAT_BUFLEN] = {0};
    struct io_output_node *io_out = NULL;

    if (NULL == pio_inf)
    {
        return;
    }

    //output io disk and io wait information
    len = snprintf(buf, IOSTAT_BUFLEN, "io_stat: rw:%lu/%lu tps:%lu time:%lu iow:%lu%%",
                   pio_inf->read_KB,
                   pio_inf->write_KB,
                   pio_inf->iotps,
                   pio_inf->iotime_ms,
                   pio_inf->iowait);

    if (pio_inf->iotop_cnt)
    {
        len += snprintf(buf + len, IOSTAT_BUFLEN - len, " Top%lu: ", pio_inf->iotop_cnt);
    }

    //output io top information
    for (i = 0; i < pio_inf->iotop_cnt; i++)
    {
        io_out = &pio_inf->iotop[i];
        len += snprintf(buf + len, IOSTAT_BUFLEN - len, "pid:%d %s rw:%u/%u; ",
                        io_out->ion->pid,
                        io_out->ion->command,
                        io_out->read_KB,
                        io_out->write_KB);

        if (0 == ((i+1) % IOSTAT_PID_IN_LINE))
        {
            pr_info("%s\n", buf);
            len = snprintf(buf, IOSTAT_BUFLEN, "io_stat: ");
        }
    }

    if ((0 == i) || (i % IOSTAT_PID_IN_LINE))
    {
        pr_info("%s\n", buf);
    }

    return;
}

/**
*   @brief:    complete initialization of hash list and all pid list.
*                  hash list used to storage pid list head, the pid list have same hash value;
*                  all pid list used to storage all the io node.
*   @param: void
*   @return: 0:init sucess; others: fail.
*/
static int io_stat_resource_init(void)
{
    io_pid_hash = (struct hlist_head *)kmalloc(sizeof(struct hlist_head) * IOSTAT_PID_HASH_LEN, GFP_KERNEL);
    if (NULL == io_pid_hash)
    {
        return -ENOMEM;
    }

    memset(io_pid_hash, 0, sizeof(struct hlist_head)*IOSTAT_PID_HASH_LEN);
    INIT_HLIST_HEAD(&io_pid_all);

    return 0;
}

/**
*   @brief:    Free the resource, delete all io node and free hash list header.
*   @param: void
*   @return: void
*/
static void io_stat_resource_exit(void)
{
    struct io_node *ion = NULL;
    struct hlist_node *temp;

    hlist_for_each_entry_safe(ion, temp, &io_pid_all, hlist)
    {
        hlist_del(&ion->hlist);//delete in all node list
        kfree(ion);
    }

    if (io_pid_hash)
    {
        kfree(io_pid_hash);
        io_pid_hash = NULL;
    }
    return;
}

/**
*   @brief:    main function to stat io information
*                  The information contain top pid io, disk io, cpu iowait.
*   @param: work: no use.
*   @return: void
*   @note: pio_inf contains "iotop", "iodisk", and "iowait".
*/
static void io_data_stat_func(struct work_struct *work)
{
    static bool first_time = true;
    static unsigned long rw_delayed_KB = 0;
    unsigned long queue_delay_time = IOSTAT_TIMER_S;

    //if have proc request, stop io stat that output to kmsg, only respond proc request.
    if (!ioinfo_enabled)
    {
        return;
    }

    memset(&io_inf, 0, sizeof(struct io_output_info));

    io_dev_stat(&io_inf);//disk io stat
    io_wait_stat(&io_inf);//iowait stat

    //don't update pid's io information immediately when io is not high
    if ((KBTOMB(io_inf.read_KB + io_inf.write_KB) > IOSTAT_TOP_DISK_THRESHOLD) ||
        (KBTOMB(rw_delayed_KB) > IOSTAT_TOP_DISK_THRESHOLD) ||
        (io_inf.iowait > IOSTAT_IOWAIT_THRESHOLD))
    {
        io_top_stat(&io_inf);//top pid io stat
        rw_delayed_KB = 0;
    }
    else
    {
        rw_delayed_KB += io_inf.read_KB + io_inf.write_KB;
        queue_delay_time = IOSTAT_TIMER_S + IOSTAT_TIMER_S;
    }

    //don't output msg at first time
    if (first_time)
    {
        first_time = false;
    }
    else
    {
        io_info_output_msg(&io_inf);
    }

    queue_delayed_work(workqueue_stat_io, &stat_io_work, queue_delay_time * HZ);
    return;
}


/**
*   @brief:    proc show function of io information
*                  The information contain all pid rw io, disk io, cpu iowait.
*   @param: m: output file handler.
*   @return: don't care.
*/
static int ioinfo_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "1\n");
    return 0;
}

static int ioinfo_open(struct inode *inode, struct file *file)
{
    return single_open(file, ioinfo_proc_show, NULL);
}

static const struct file_operations proc_info_operations =
{
    .open       = ioinfo_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

/**
*   @brief:    creat "proc/ioinfo" that show device io and task top io;
*                  creat io stat workqueue that output io msg.
*   @param: void.
*   @return:  0.
*/
static int __init io_info_init(void)
{
    proc_create("ioinfo", 0, NULL, &proc_info_operations);

    if (0 == io_stat_resource_init())
    {
        INIT_DELAYED_WORK(&stat_io_work, io_data_stat_func);
        workqueue_stat_io = create_workqueue("workqueue_stat_io");
        queue_delayed_work(workqueue_stat_io, &stat_io_work, 10 * HZ);
        pr_info("io_stat: resource init success.\n");
    }
    else
    {
        pr_err("io_stat:ERR: resource init failed.\n");
    }
    return 0;
}

static void __exit io_info_exit(void)
{
    pr_info("io_stat: resource have free.\n");
    io_stat_resource_exit();
}

module_init(io_info_init);
module_exit(io_info_exit);
