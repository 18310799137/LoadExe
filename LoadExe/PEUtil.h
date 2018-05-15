#pragma once
/**
 * 修复导入表
 */
void restoreIBuffImpTable(PThePeHeaders  thePeHeaders);



/* 修复重定位表 拉伸后的状态*/
void restoreIbuffRelocationTable(char * _i_buff);