import numpy as np
# !/usr/bin/python3
import pymysql
import time
import scipy.io as sio # 重新安装该库
import random
import os
import json
from lshash import LSHash
DB_INFO = {'host':'127.0.0.1','port':3306,'DB':'YJ_TEST','TB':'test0911'}
folder = 'D:/DOCYJ/Test20190520/'
mat_file = 'tensorsqlite.mat'
mat_folder = 'data/matfile/'
binary_file = 'binaryname_new.txt'
binary_folder = 'data/dim5/'
result_file = 'result.txt'
select_result_folder = 'result/'
funcname_f = 'sqlitefunc/'

# 数据库操作类
class DB_Actor():
    # 初始化数据库连接，配置信息见全局变量
    def __init__(self):
        global DB_INFO
        self.conn = pymysql.Connect(host=DB_INFO['host'], port=DB_INFO['port'],\
                               user='root', passwd='jiang', db=DB_INFO['DB'], charset='utf8')
        self.cursor = self.conn.cursor()
        self.CreateTB(DB_INFO['TB'])

    # 创建表格
    def CreateTB(self,DBname):
        sql = "create table " + DBname + " (binary_name VARCHAR(100) NOT NULL,\
                                            function_name VARCHAR(100) NOT NULL,\
                                            feature VARCHAR(5000) NOT NULL)"
        try:
            self.cursor.execute(sql)
            print('create db %s success.' %(DBname))
        except Exception as e:
            print(e)

    # 执行SQL语句
    def DoSql(self,SQL):
        try:
            self.cursor.execute(SQL)
            self.conn.commit()
            # print(SQL,'success')
        except Exception as e:
            print(e,SQL)
            self.conn.rollback()

    # 删除表格
    def DropTB(self,DBname):
        sql = "drop table " + DBname
        try:
            self.cursor.execute(sql)
            print('table:',DBname,'drop success')
        except Exception as e:
            print(e,sql)

    # 展示数据库数据
    def ShowDB(self,DBname):
        sql = "select * from " + DBname
        try:
            self.cursor.execute(sql)
            rows = self.cursor.fetchall()
            for row in rows:
                print(row)
        except Exception as e:
            print(e,sql)

    # 断开数据库连接
    def CutLink(self):
        self.cursor.close()
        self.conn.close()

# 数据分析与保存类
class Date_Analysis():
    # 初始化数据精度，生成数据库实例
    def __init__(self):
        global DB_INFO
        self.accuracy = 6 # 设置精度小数位数
        self.table = DB_INFO['TB']
        self.DOSQL = DB_Actor()
        # self.DOSQL.CreateTB(self.table)

    def eachFile(self,filepath):
        child=[]
        pathDir =  os.listdir(filepath)
        for allDir in pathDir:
            child.append(os.path.join('%s%s' % (filepath, allDir)))
        return child

    # 数据分析主过程
    def MainAnalysis(self,binary_folder,mat_folder,folder):
        matfolder_list = self.eachFile(mat_folder)
        binary_name = ''
        func_addr = ''
        for eachmatfolder in matfolder_list:
            matfile_list = self.eachFile(eachmatfolder + '/')
            if eachmatfolder.find('clang')!=-1:
                binary_name = 'openssl-clang-o3'
                func_addr = binary_folder + 'openssl-clang-o3.json'
            elif eachmatfolder.find('gcc')!=-1:
                binary_name = 'openssl-gcc-o3'
                func_addr = binary_folder + 'openssl-gcc-o3.json'
            func_handle = open(func_addr, 'r')
            func_contents = func_handle.readlines()
            for eachmatfile in matfile_list:
                matfile_name = eachmatfile.split('/')[-1].split('.')[0]
                func_index = int(matfile_name.split('ssl')[1])
                func_name_dict = json.loads(func_contents[func_index])
                func_name = func_name_dict['fname']
                ch_index = self.JudgeCharIndex(func_name)
                func_name = func_name[ch_index:]

                s_data = self.GetSourceMat(eachmatfile)
                feature_array = self.featureM2L(s_data)
                if self.JudgeNorZero(feature_array):  # 全零
                    pass
                else:
                    temp = self.DataAccuray(feature_array)
                    str_data = temp.astype(str)
                    feature = "#".join(str_data)
                    print(binary_name, func_name, feature)
                    self.SaveData(binary_name, func_name, feature)
            func_handle.close()
        self.DOSQL.CutLink()


    # 截取前60个特征值
    def featureM2L(self,matrix):
        ret = []
        for i in range(60):
            if i < len(matrix):
                ret.append(matrix[i][0])
            else:
                ret.append(float(0))
        return np.array(ret)


    def ResultAnalysis(self,res_addr,select_addr):
        '''
        result_handle = open(res_addr,'r')
        select_handle = open(select_addr,'a')
        result_contents = result_handle.readlines()
        for res in result_contents:
            feature_list = res.split(',')
            feature_array = self.ListStr2ArrayFloat(feature_list)
            temp = self.DataAccuray(feature_array)
            str_data = temp.astype(str)
            feature = "-".join(str_data)
            print(feature)
            exit()

            rows = self.DatafromFeature(feature)
            select_data = rows[0]
            select_handle.write(select_data+'\n')
            print(rows)
        result_handle.close()
        select_handle.close()
        '''
        feature = '0.008346-0.008392-0.005623-0.021094-0.004259-0.00653-4e-06-0.001683-0.00178-0.002022-0.001373-0.000187-0.005874-0.000901-0.003495'
        rows = self.DatafromFeature(feature,0,20)
        select_data = ''
        for row in rows:
            row_data = row[0] + ':' + row[1]
            select_data = select_data + row_data + '#'
        print(select_data)



    # 根据feature查询数据库 从0开始,num表示查询数量 注意limit是返回查询结果中的指定行数
    def DatafromFeature(self,feature,sta,num):
        res = []
        sql = "select * from " + self.table + " LIMIT " + str(sta) + ',' + str(num)
        self.DOSQL.cursor.execute(sql)
        rows = self.DOSQL.cursor.fetchall()
        for row in rows:
            if row[2] == feature:
                res.append(row)
                break
            else:
                pass
        return res

    # 字符串list转浮点数array
    def ListStr2ArrayFloat(self,data):
        for i in range(0,len(data)):
            data[i] = float(data[i])
        return np.array(data)

    # 修改数据精度np.array float类型
    def DataAccuray(self,data):
        i = 0
        for num in data:
            data[i] = round(num, self.accuracy)
            i = i + 1
        return data

    # 判断是否全零
    def JudgeNorZero(self,data):
        for num in data:
            if num != 0.0:
                return 0
        return 1

    # 找到字符串第一个字母的位置，用于裁剪字符串开头的破折号
    def JudgeCharIndex(self,s):
        i = 0
        for ch in s:
            if ch >= 'a' and ch <= 'z':
                return i
            elif ch >= 'A' and ch <= 'Z':
                return i
            else:
                i=i+1

    # 读取.mat文件
    def GetSourceMat(self,Mat_addr):
        m = sio.loadmat(Mat_addr)
        return m['FE']

    # 保存数据库
    def SaveData(self,binary_name,fun_name,feature):
        sql = "insert into " + self.table + " (binary_name,function_name,feature) values('" + binary_name + "','" + fun_name + "','" + feature  + "')"
        self.DOSQL.DoSql(sql)

    # 确定保留小数
    def as_num(self,x):
        y = '{:.6f}'.format(x)
        return y

    # def JudgeNorSave(self,data)

class LSHAnalysis():
    def __init__(self):
        global DB_INFO
        self.table = DB_INFO['TB']
        self.DODB = DB_Actor()
        self.SelectDB = Date_Analysis()
        pass


    def searchnew(self,test,model,s_key):
        # testindex=list()
        i = 0
        totaly = []
        #for testi in range(len(test)):
            #print
        #test[testi]
        testindex = list()
        #y = []
        for modeli in range(len(model)):

            # dis = np.linalg.norm(np.array(test) - np.array(model[modeli]))
            dis = abs(np.sum(test) - np.sum(model[modeli]))
            testindex.append({'index': modeli, 'dis': dis})
            
            #i = i + 1
        testindex.sort(key=lambda x: x['dis'], reverse=False) # 升序
        for x in testindex[0:s_key]:
            totaly.append(x['index'])
        #totaly.append(y)
        # print(totaly)
        return totaly
    # key表示获得相似feature的个数
    def Mainfunc(self,mat_folder,result_folder,binary_folder,key):
        FUNCTIONNUMBER={'openssl-clang-o3':494,
                        'openssl-gcc-o3':333,
                                                }
        binaryname_list = self.SelectDB.eachFile(binary_folder)
        FUNCTIONNAME = []
        for binary_content in binaryname_list:
            FUNCTIONNAME.append(binary_content.split('/')[-1].split('.')[0])
        print(FUNCTIONNAME)


        #core 只针对DIR
        imodel_name = 'openssl-gcc-o3'
        imodel_BIN_name = 'openssl-gcc-o3'
        imodel_matindex = 'gcc'
        # 输入binanry全称


        imdel_s = self.GetSqlStart(FUNCTIONNUMBER,FUNCTIONNAME,imodel_BIN_name)
        # 确定数据库范围
        imodel_s_n = [imdel_s,FUNCTIONNUMBER[imodel_BIN_name]]
        print(imodel_name,imodel_s_n)

        itest_name = 'openssl-clang-o3'
        itest_BIN_name = 'openssl-clang-o3'
        itest_matindex = 'clang'
        itest_s = self.GetSqlStart(FUNCTIONNUMBER,FUNCTIONNAME,itest_BIN_name)
        itest_s_n = [itest_s,FUNCTIONNUMBER[itest_BIN_name]]
        print(itest_name,itest_s_n)


        ######## 两两对比
        n1 = 60
        data = np.zeros((n1,4000))
        test = np.zeros((n1,4000))
        model_num = 0
        test_num = 0

        matfolder_list = self.SelectDB.eachFile(mat_folder)
        for eachmatfolder in matfolder_list:
            matfile_list = self.SelectDB.eachFile(eachmatfolder + '/')
            if eachmatfolder.find(imodel_matindex) != -1:
                for eachmatfile in matfile_list:

                    data[:, model_num] = self.SelectDB.featureM2L(self.SelectDB.GetSourceMat(eachmatfile))
                    model_num = model_num + 1
            elif eachmatfolder.find(itest_matindex) != -1:
                for eachmatfile in matfile_list:
                    test[:, test_num] = self.SelectDB.featureM2L(self.SelectDB.GetSourceMat(eachmatfile))
                    test_num = test_num + 1
        dataves = np.transpose(data)
        testves = np.transpose(test)
    #    output_total = open(result_folder + 'result_total.txt', 'w')

        model = np.zeros((model_num, n1))
        lsh_model = LSHash(7, n1)
        for jj in range(model_num):
            lsh_model.index(dataves[jj, :])
            model[jj, :] = dataves[jj, :]


        test = np.zeros((test_num, n1))
        for ii in range(test_num):
            test[ii, :] = testves[ii, :]


        ##############################################################################
        itest_func_list = self.GetFuncListFromFeature(test,itest_s_n[0],itest_s_n[1])
        imodel_func_list = self.GetFuncListFromFeature(model,imodel_s_n[0],imodel_s_n[1])
        print('target_list get success\n')

        Inmodel_Total = self.GetInmodelTotal(imodel_func_list,itest_func_list)
        # Inmodel_Total = len(itest_func_list)
        # Inmodel_NUM = 0.0
        output = open(result_folder + 'KeyBetweenBySumFindStr0911' + '.txt', 'a')
        # SelectDB = Date_Analysis()
        for key in [1,10,20]:
            Inmodel_NUM = 0.0
            for queryi in range(test_num):
                # key = 1
                test_funcname = itest_func_list[queryi]
                print('Start find func:',test_funcname)
                # print(test[queryi, :])
                # print(test[queryi, :].any() != 0)
                if test[queryi, :].any() != 0:
                    #Atemp = lsh_model.query(test[queryi, :], key, 'euclidean')
                    #print(test[queryi,:])
                    Atemp=self.searchnew(test[queryi,:], model, key)
                    for i in range(len(Atemp)):
                        try:
                            ## 根据下标直接获取function
                            select_funcname = imodel_func_list[int(Atemp[i])]
                            lentar = len(select_funcname.split('_'))
                            issame = False
                            for ilentar in range(lentar):
                                tempp = select_funcname.split('_')[ilentar]
                               # print(tempp)
                                if test_funcname.find(tempp)!=-1:
                                    issame = True
                                    break
                            #if test_funcname.strip(' ').strip('\n')==select_funcname.strip(' ').strip('\n'):
                            if issame:
                                Inmodel_NUM = Inmodel_NUM + 1
                                print('Get One')
                                break
                            else:
                                print(test_funcname,':',select_funcname)
                                pass
                            # if test_funcname.find(select_funcname)!=-1:
                            #     Inmodel_NUM = Inmodel_NUM + 1
                            #     print('Get One')
                            #     break
                            # else:
                            #     print(test_funcname + ' ! ' + select_funcname)
                            #     pass
                        except Exception as e:
                            print(e)
                            print(str(Atemp[i]))
                    # else:
                    #     print('AtempLen:',len(Atemp),' ','key:',key)
                    #     continue
                else:
                    print('feature==0')
            res = str(float('%.4f' % (Inmodel_NUM/Inmodel_Total)))
            msg = itest_name + '----->' + imodel_name + \
                  ' Res:' + res + ' Inmodel_NUM:' + str(Inmodel_NUM) + ' Inmodel_Total:' + str(Inmodel_Total) +\
                ' Test_NUM:' + str(len(test)) + ' Model_NUM:' + str(len(model)) +\
                    ' Key:' + str(key)
            output.write(msg + '\n')
            print(msg)
        output.close()

    def GetInmodelTotal(self,model_func,test_func):
        total = 0
        for t_func in test_func:
            if t_func in model_func:
                total=total+1
        return total

    def GetFuncListFromFeature(self,featurelist,sta,num):
        target_list = []
        # 获取test的所有funcname
        for queryi in range(len(featurelist)):
            target = featurelist[queryi, :]
            # print(target)
            if target.any() != 0:
                temp_target = self.SelectDB.DataAccuray(target)
                str_target = temp_target.astype(str)
                feature_target = "#".join(str_target)
                # print(feature_target)
                rows = self.SelectDB.DatafromFeature(feature_target,sta,num)
                target_funcname = rows[0][1]
                target_list.append(target_funcname)
                print(target_funcname)
        return target_list


    def Row2Str(self,rows):
        data = ''
        for row in rows:
            # row_data = row[0] + ':' + row[1] + ':' + row[2]
            row_data = row[0] + ':' + row[1]
            data = data + row_data + '#'
        return data

    def Row2Dict(self,row):
        res = {'binary_name':row[0],'function_name':row[1]}
        return res


    # 清除空格
    def ClearStr(self,data):
        res = ''
        for ch in data:
            if ch != '_':
                res = res + ch
            else:
                pass
        return res

    # 比较两字符串是否相似
    def CompareStr(self,target,test):
        target = self.ClearStr(target)
        test = self.ClearStr(test)
        n = len(target)-3
        for i in range(0,n):
            temp = target[i:i+5]
            if test.find(temp) != -1:
                return 1
        return 0

    # 获取当前M的值sour是所有base里的数据，字符串，target是要判断的数据
    def GetGlobalM(self,func):
      #  m = 0
        sql = "select * from " + self.table + " where function_name = " + "'" + func + "'"
        # 查询记录数
        # sql = "select * from test where binary_name='busybox_X86_O3'"
        self.DODB.cursor.execute(sql)
        rows = self.DODB.cursor.fetchall()
        return len(rows)

    # funcnum DICT   funcname LIST   target STR
    def GetSqlStart(self,funcnum,funcname,target):
        n = funcname.index(target)
        sta = 0
        for i in range(0,n):
            temp = funcnum[funcname[i]]
            sta = sta + temp
        return sta




if __name__ == "__main__":

    # DOAnalysis = Date_Analysis()
    # keylist = [i for i in range(1,200)]

    #base = 10
    key = 1
    DOlsh = LSHAnalysis()
    DOlsh.Mainfunc(folder+mat_folder,folder+select_result_folder,folder+binary_folder,key)

# 0,3884
# 9172,2284
#     DODB = DB_Actor()
    # 创建数据库
    # create database YJ_TEST;
    # 查询某条记录
    # sql = "select * from test0523 where function_name = 'fts3EvalStartReaders'"
    # 查询记录数
    # sql = "select * from test where binary_name='coreutils_dir_X86_O0'"
    # sql = "select * from " + DB_INFO['TB'] + " where binary_name='" + \
    #      'openssl-gcc-o3' + "'"
    # sql = "select * from test0520 LIMIT 9172,2285"

    # sql = "select * from " + DB_INFO['TB'] + " where binary_name='" + \
    #      'sqlite_x86_o0' + \
    #      "'" + \
    #      " limit " + str(2271) + ',' + str(1)
    # print(sql)
    #
    #
    # DODB.cursor.execute(sql)
    # rows = DODB.cursor.fetchall()
    # print(len(rows))

    # 清空数据库表格
    # DODB.DropTB(DB_INFO['TB'])

    # 数据分析并保存数据库
    # DOAnalysis.MainAnalysis(folder+binary_folder,folder+mat_folder,folder)

    # 根据feature查询数据库
    # DOAnalysis.ResultAnalysis(folder+result_file,folder+result_file)

    # str与float转换
    # x = float('0.1234')
    # y = str(x)
    # print(type(x),type(y))

    # array与list转换
    # a = list()
    # b = np.array(a)
    # c = b.tolist()


    # 展示数据库数据
    # DODB.ShowDB(DB_INFO['TB'])

    # 断开数据库连接
    # DODB.CutLink()



