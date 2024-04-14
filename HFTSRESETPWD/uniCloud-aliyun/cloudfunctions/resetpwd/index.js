'use strict';

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

exports.main = async (event, context) => {
  //event为客户端上传的参数
  // console.log('event : ' + event)
    let{email,checkcode,newpwd}=event

	var mysql = require('mysql');
	var connection = mysql.createConnection({
	  host: '192.168.1.2',
	  user: 'xxx',
	  password: 'xxx',
	  database: 'xxxxx',
	  port: 3306
	});
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
	      } else {
	        resolve(results)
	      }
	    })
	  })
	}

  try {

    connection.connect()
     

    var addRes = await query('SELECT * FROM users WHERE email =?',[email])
	var stringRes =  JSON.stringify(addRes);
	var jsonArray = JSON.parse(stringRes);
	const randomString = generateRandomString(64);
	
	if(jsonArray[0].checkcode == checkcode ){
		await query('UPDATE users SET password = ? WHERE email = ?',[newpwd,email])
		await query('UPDATE users SET checkcode = ? WHERE email = ?',[randomString,email])
		connection.end();
		return 200;
	}else{
		connection.end();
		return 500;
	}
	
	
  } catch (e) {
	  
    return null;
	
  }
	
};
