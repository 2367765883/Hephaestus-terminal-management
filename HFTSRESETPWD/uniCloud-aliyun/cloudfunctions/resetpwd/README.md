这是一个在云函数中连接 mysql 数据库的简易示例，供有需要的开发者参考。

代码很简单，几个注意事项：

1. 注意修改代码示例中的 mysql server 地址及鉴权密码

```
var connection = mysql.createConnection({
    host: 'mysql-server-adress',
    user: 'root',
    password: 'password',
    database: 'dbname',
    port: 3306
});
```

2. 需提前安装 mysql 依赖，本示例的 node_modules 已内置
3. 注意：云函数中不支持异步回调方式，需封装为 `Promise`调用

```
/**
 * 封装mysql执行操作为Promise
 * 
 * @param {Object} sql
 * @param {Object} values
 */
const query = function(sql, values) {
    return new Promise((resolve, reject) => {
        connection.query(sql, values, (error, results, fields) => {
            if (error) {
              reject(error)
            }else{
              resolve(results)
            }
            
        })
    })
}
```

4. mysql 的增删改查示例如下，更多 mysql 用法参考：[https://github.com/mysqljs/mysql](https://github.com/mysqljs/mysql)

```
try {
    //连接数据库
    connection.connect()

    // 新增记录
    let addRes = await query('insert into users set ?', {
        name: '丁元英',
        age: 40
    })
    console.log("新增记录：", addRes)

    // 删除记录
    let delRes = await query('delete from users where name=? ', ['韩楚风'])
    console.log("删除记录：", delRes)

    //修改记录
    let updateRes = await query('update users set age=? where name=? ', [50, '丁元英'])
    console.log("修改记录：", updateRes)

    //查询记录
    let queryRes = await query('select * from users where name=? ', ['丁元英'])
    console.log("查询记录：", queryRes)

    //关闭连接
    connection.end();
} catch (e) {
    console.log('操作失败，失败信息 ', e);
}
```
