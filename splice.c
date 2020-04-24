  /****************
   * SPLICING 拼接 *
   ****************/

  /* 这是最后一招，由一整轮没有发现的结果触发。
     它获取当前输入文件，随机选择另一个输入，并以一定的偏移量将它们拼接在一起，然后依靠破坏代码来使该blob突变   */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* 首先，如果我们修改了in_buf来为havoc做准备，让我们清理一下 */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* 选择一个随机队列条目并拿到它。不要自拼接 */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* 确保目标长度合适 */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* 将测试用例读入新缓冲区 */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. 
       在第一个和最后一个不同的字节之间找到合适的拼接位置。
       如果差异仅是一个字节左右，就排除（还有保释、舀水的意思)。  */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. 
        在第一个和最后一个不同的字节之间拆分    */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. 实施操作 */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }
