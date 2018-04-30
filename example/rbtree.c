// ©.
// https://github.com/sizet/lkm_rbtree

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/rbtree.h>




#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_INFO "%s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)




// 要記錄的資料, 記錄每個產品的名稱和價格.
struct product_t
{
    // 紅黑樹節點.
    struct rb_node tnode;
    // 產品名稱.
    char name[16];
    // 產品價格.
    unsigned int price;
};

// 宣告紅黑樹樹根並初始化.
struct rb_root product_tree = RB_ROOT;




// 找到資料所在的位置.
static int rbtree_search_product_by_name(
    char *product_name,
    struct product_t **product_data_buf)
{
    struct rb_node *each_tnode;
    struct product_t *each_product;
    int ret;


    // 從樹根開始尋找.
    each_tnode = product_tree.rb_node;
    while(each_tnode != NULL)
    {
        each_product = rb_entry(each_tnode, struct product_t, tnode);

        ret = strcmp(product_name, each_product->name);
        if(ret < 0)
        {
            each_tnode = each_tnode->rb_left;
        }
        else
        if(ret > 0)
        {
            each_tnode = each_tnode->rb_right;
        }
        else
        {
            *product_data_buf = each_product;
            return 0;
        }
    }

    return -1;
}

// 將資料加入紅黑樹.
static int rbtree_add(
    struct product_t *product_data)
{
    struct rb_node **each_tnode, *parent_tnode = NULL;
    struct product_t *each_product;
    int ret;


    // 需要修改樹節點的內容, 需要使用雙重指標.
    each_tnode = &(product_tree.rb_node);
    // 等於 NULL 表示找到插入的位置.
    while(*each_tnode != NULL)
    {
        parent_tnode = *each_tnode;

        each_product = rb_entry(*each_tnode, struct product_t, tnode);

        ret = strcmp(product_data->name, each_product->name);
        if(ret < 0)
        {
            // 取得指向左節點的指標的位置.
            each_tnode = &((*each_tnode)->rb_left);
        }
        else
        if(ret > 0)
        {
            // 取得指向右節點的指標的位置.
            each_tnode = &((*each_tnode)->rb_right);
        }
        else
        {
            DMSG("product already exist [%s/%u]", each_product->name, each_product->price);
            return -1;
        }
    }

    // 取得空間.
    each_product = (struct product_t *) kmalloc(sizeof(struct product_t), GFP_KERNEL);
    if(each_product == NULL)
    {
        DMSG("call kmalloc() fail");
        return -1;
    }

    // 複製資料.
    memcpy(each_product, product_data, sizeof(struct product_t));

    // 加入到紅黑樹.
    rb_link_node(&(each_product->tnode), parent_tnode, each_tnode);
    rb_insert_color(&(each_product->tnode), &product_tree);
    DMSG("add [%s/%u]", each_product->name, each_product->price);

    return 0;
}

// 將資料從紅黑樹刪除.
static int rbtree_del(
    char *product_name)
{
    struct product_t *each_product;


    // 檢查資料是否存在.
    if(rbtree_search_product_by_name(product_name, &each_product) < 0)
    {
        DMSG("not find product [%s]", product_name);
        return -1;
    }

    // 從紅黑樹刪除.
    DMSG("del [%s/%u]", each_product->name, each_product->price);
    rb_erase(&(each_product->tnode), &product_tree);
    kfree(each_product);

    return 0;
}

// 透過產品名稱從紅黑樹取出產品資料.
static int rbtree_get(
    char *product_name)
{
    struct product_t *each_product;


    // 檢查資料是否存在.
    if(rbtree_search_product_by_name(product_name, &each_product) < 0)
    {
        DMSG("not find product [%s]", product_name);
        return -1;
    }

    DMSG("product [%s/%u]", each_product->name, each_product->price);

    return 0;
}

// 顯示紅黑樹的所有資料.
static int rbtree_dump(
    void)
{
    struct rb_node *each_tnode, *parent_tnode;
    struct product_t *each_product, *parent_product;


    // 中序走訪 (左到右).
    DMSG("dump, in-order (left to right) :");
    for(each_tnode = rb_first(&product_tree);
        each_tnode != NULL;
        each_tnode = rb_next(each_tnode))
    {
        each_product = rb_entry(each_tnode, struct product_t, tnode);
        parent_tnode = rb_parent(each_tnode);
        if(parent_tnode == NULL)
        {
            DMSG("product [%s/%u], is root", each_product->name, each_product->price);
        }
        else
        {
            parent_product = rb_entry(parent_tnode, struct product_t, tnode);
            DMSG("product [%s/%u], is [%s] %s",
                 each_product->name, each_product->price, parent_product->name,
                 parent_product->tnode.rb_left == each_tnode ? "left" : "right");
        }
    }

    // 中序走訪 (右到左).
    DMSG("dump, in-order (right to left) :");
    for(each_tnode = rb_last(&product_tree);
        each_tnode != NULL;
        each_tnode = rb_prev(each_tnode))
    {
        each_product = rb_entry(each_tnode, struct product_t, tnode);
        parent_tnode = rb_parent(each_tnode);
        if(parent_tnode == NULL)
        {
            DMSG("product [%s/%u], is root", each_product->name, each_product->price);
        }
        else
        {
            parent_product = rb_entry(parent_tnode, struct product_t, tnode);
            DMSG("product [%s/%u], is [%s] %s",
                 each_product->name, each_product->price, parent_product->name,
                 parent_product->tnode.rb_left == each_tnode ? "left" : "right");
        }
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
    // 後序走訪 (左到右).
    DMSG("dump, post-order (left to right) :");
    for(each_tnode = rb_first_postorder(&product_tree);
        each_tnode != NULL;
        each_tnode = rb_next_postorder(each_tnode))
    {
        each_product = rb_entry(each_tnode, struct product_t, tnode);
        parent_tnode = rb_parent(each_tnode);
        if(parent_tnode == NULL)
        {
            DMSG("product [%s/%u], is root", each_product->name, each_product->price);
        }
        else
        {
            parent_product = rb_entry(parent_tnode, struct product_t, tnode);
            DMSG("product [%s/%u], is [%s] %s",
                 each_product->name, each_product->price, parent_product->name,
                 parent_product->tnode.rb_left == each_tnode ? "left" : "right");
        }
    }
#endif

    return 0;
}

// 刪除紅黑樹所有的資料, 方法一 : 使用後序走訪直接釋放資料.
static int rbtree_clear_method1(
    struct rb_node *this_tnode)
{
    struct product_t *each_product;


    if(this_tnode->rb_left != NULL)
        rbtree_clear_method1(this_tnode->rb_left);
    if(this_tnode->rb_right != NULL)
        rbtree_clear_method1(this_tnode->rb_right);

    each_product = rb_entry(this_tnode, struct product_t, tnode);
    DMSG("del [%s/%u]", each_product->name, each_product->price);
    kfree(each_product);

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
// 刪除紅黑樹所有的資料, 方法二 : 使用後序走訪並逐一刪除節點.
static int rbtree_clear_method2(
    void)
{
    struct product_t *each_product, *tmp_product;


    rbtree_postorder_for_each_entry_safe(each_product, tmp_product, &product_tree, tnode)
    {
        DMSG("del [%s/%u]", each_product->name, each_product->price);
        rb_erase(&(each_product->tnode), &product_tree);
        kfree(each_product);
    }

    return 0;
}
#endif

// 刪除紅黑樹所有的資料.
static int rbtree_clear(
    void)
{

    // 方法一, 使用後序走訪直接釋放資料.
    if(product_tree.rb_node != NULL)
    {
        rbtree_clear_method1(product_tree.rb_node);
        product_tree = RB_ROOT;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
    // 方法二 : 使用後序走訪並逐一刪除節點
    rbtree_clear_method2();
#endif

    return 0;
}

#define PARAMETER_DATA_SPLIT_KEY  ' '
#define PARAMETER_VALUE_SPLIT_KEY '='

struct parameter_record_t
{
    char *data_name;
    char *data_value;
    unsigned int is_must;
};

enum PARA_RECORD_INDEX_LIST
{
    PR_OPERATE_INDEX = 0,
    PR_NAME_INDEX,
    PR_PRICE_INDEX,
};
struct parameter_record_t para_record_list[] =
{
    {"operate", NULL, 1},
    {"name",    NULL, 0},
    {"price",   NULL, 0},
    {NULL, NULL, 0}
};

static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos);

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos);

static char *node_name = "rbtree";
static struct proc_dir_entry *node_entry;
static struct file_operations node_fops =
{
    .read  = node_read,
    .write = node_write,
};




static int split_parameter(
    char **para_con_buf,
    size_t *para_len_buf,
    char **data_name_buf,
    char **data_value_buf)
{
    char *pcon;
    size_t plen, idx1, idx2, more_para = 0;


    pcon = *para_con_buf;
    plen = *para_len_buf;

    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] != PARAMETER_DATA_SPLIT_KEY)
            break;
    if(idx1 > 0)
    {
        pcon += idx1;
        plen -= idx1;
    }

    if(plen == 0)
        return 0;

    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] == PARAMETER_DATA_SPLIT_KEY)
        {
            pcon[idx1] = '\0';
            more_para = 1;
            break;
        }

    for(idx2 = 0; idx2 < idx1; idx2++)
        if(pcon[idx2] == PARAMETER_VALUE_SPLIT_KEY)
        {
            pcon[idx2] = '\0';
            break;
        }

    *data_name_buf = pcon;

    *data_value_buf = idx2 < idx1 ? pcon + idx2 + 1 : NULL;

    idx1 += more_para;
    *para_con_buf = pcon + idx1;
    *para_len_buf = plen - idx1;

    return 1;
}

static int parse_parameter(
    char *para_con,
    size_t para_len,
    struct parameter_record_t *target_list)
{
    struct parameter_record_t *each_pr;
    char *tmp_name, *tmp_value;


    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        each_pr->data_value = NULL;

    while(1)
    {
        if(split_parameter(&para_con, &para_len, &tmp_name, &tmp_value) == 0)
            break;

        for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
            if(strcmp(each_pr->data_name, tmp_name) == 0)
            {
                if(tmp_value == NULL)
                {
                    DMSG("miss value [%s]", each_pr->data_name);
                    return -1;
                }

                if(each_pr->data_value != NULL)
                {
                    DMSG("duplic data [%s]", each_pr->data_name);
                    return -1;
                }

                each_pr->data_value = tmp_value;
                break;
            }

        if(each_pr->data_name == NULL)
        {
            DMSG("unknown parameter [%s]", tmp_name);
            return -1;
        }
    }

    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        if(each_pr->data_value == NULL)
            if(each_pr->is_must != 0)
            {
                DMSG("miss data [%s]", each_pr->data_name);
                return -1;
            }

    return 0;
}

static int process_parameter(
    char *para_con,
    size_t para_len)
{
    struct parameter_record_t *pr_name = NULL, *pr_price = NULL, *pr_operate;
    struct product_t product_data;


    if(parse_parameter(para_con, para_len, para_record_list) < 0)
    {
        DMSG("call parse_parameter() fail");
        return -1;
    }

    memset(&product_data, 0, sizeof(product_data));

    pr_name = para_record_list + PR_NAME_INDEX;
    if(pr_name->data_value != NULL)
    {
        snprintf(product_data.name, sizeof(product_data.name), "%s", pr_name->data_value);
        DMSG("name  = %s", product_data.name);
    }

    pr_price = para_record_list + PR_PRICE_INDEX;
    if(pr_price->data_value != NULL)
    {
        product_data.price = simple_strtoul(pr_price->data_value, NULL, 10);
        DMSG("price = %u", product_data.price);
    }

    pr_operate =   para_record_list + PR_OPERATE_INDEX;
    if(strcmp(pr_operate->data_value, "add") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(pr_price->data_value == NULL)
        {
            DMSG("price can not be empty");
            return -1;
        }

        if(rbtree_add(&product_data) < 0)
        {
            DMSG("call rbtree_add() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "del") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }

        if(rbtree_del(product_data.name) < 0)
        {
            DMSG("call rbtree_del() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "get") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }

        if(rbtree_get(product_data.name) < 0)
        {
            DMSG("call rbtree_get() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "dump") == 0)
    {
        if(rbtree_dump() < 0)
        {
            DMSG("call rbtree_dump() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "clear") == 0)
    {
        if(rbtree_clear() < 0)
        {
            DMSG("call rbtree_clear() fail");
            return -1;
        }
    }

    return 0;
}

static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos)
{
    // 使用方式 : echo "command" > /proc/linklist
    DMSG("usage :");
    DMSG("  echo \"<command>\" > /proc/%s", node_name);

    // 增加產品資料, 例如 :
    // echo "operate=add name=pen price=25" > /proc/linklist
    DMSG("add product :");
    DMSG("  operate=add name=<name> price=<price>");

    // 刪除某個產品資料, 例如 :
    // echo "operate=del name=pen" > /proc/linklist
    DMSG("del product :");
    DMSG("  operate=del name=<name>");

    // 取得某個產品的資料, 例如 :
    // echo "operate=get name=pen" > /proc/linklist
    DMSG("get product data :");
    DMSG("  operate=get name=<name>");

    // 顯示全部的產品資料, 例如 :
    // echo "operate=dump" > /proc/linklist
    DMSG("dump all product :");
    DMSG("  operate=dump");

    // 刪除全部的產品資料, 例如 :
    // echo "operate=clear" > /proc/linklist
    DMSG("del all product :");
    DMSG("  operate=clear");

    return 0;
}

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos)
{
    char read_buf[256];
    size_t rlen = sizeof(read_buf) - 1;


    memset(read_buf, 0, sizeof(read_buf));
    rlen = count >= rlen ? rlen : count;
    copy_from_user(read_buf, buffer, rlen);
    if(rlen > 0)
        if(read_buf[rlen - 1] == '\n')
        {
            rlen--;
            read_buf[rlen] = '\0';
        }

    if(process_parameter(read_buf, rlen) < 0)
    {
        DMSG("call process_parameter() fail");
    }

    return count;
}

static int __init main_init(
    void)
{
    if((node_entry = proc_create(node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &node_fops)) == NULL)
    {
        DMSG("call proc_create(%s) fail", node_name);
        return 0;
    }

    return 0;
}

static void __exit main_exit(
    void)
{
    remove_proc_entry(node_name, NULL);

    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Che-Wei Hsu");
MODULE_DESCRIPTION("Red-Black Tree");
