<script>
	export default {
		data() {
			return {
				email: '',
				checkcode:'',
				newpwd:''
			};
		},
		onLoad() {

		},
		methods: {
			resetpwd: function () {
				if(this.email==null || this.checkcode==null || this.newpwd==null)
				{
					alert('数据填充失败！')
					return
				}
			       uniCloud.callFunction({
			           name:'resetpwd',
			           data:{
			                   email:this.email,
							   checkcode:this.checkcode,
							   newpwd:this.newpwd
			           },
			           success:res=>{
						   console.log(res.result)
			                   if(res.result == 500){
								   alert('请重新核对信息！')
							   }
							   if(res.result == 200){
							   	    alert('修改成功！')							  
							   }
							   if(res.result == null){
							   	    alert('提交数据有误！')							  
							   }
			           }
			       })
			    },
		}
	}
</script>


<template>
  <!-- 整体背景 -->
  <div class="login-wrap">
    <!--输入框-->
    <div class="form-wrapper">
      <div class="header">
       密码重设
      </div>
      <div class="input-wrapper">
        <div class="border-wrapper">
          <input type="text" v-model="email"  placeholder="注册时邮箱" class="border-item" autocomplete="off" />
        </div>
		<div class="border-wrapper">
		  <input type="text" v-model="checkcode"  placeholder="令牌" class="border-item" autocomplete="off" />
		</div>
        <div class="border-wrapper">
          <input type="newpassword" v-model="newpwd"  placeholder="新密码" class="border-item" autocomplete="off" />
        </div>
      </div>
      <div class="action">
        <div class="btn" @click="resetpwd">确定</div>
      </div>
    </div>
  </div>
</template>




<style scoped>
.login-wrap {
  height: 100%;
  font-family: JetBrains Mono Medium;
  display: flex;
  align-items: center;
  justify-content: center;
  /* background-color: #0e92b3; */
  background: url('./static/back.jpg');
  background-size: 100% 100%;
}
 
.form-wrapper {
  width: 300px;
  background-color: rgba(41, 45, 62, 0.8);
  color: #fff;
  border-radius: 2px;
  padding: 50px;
}
 
.form-wrapper .header {
  text-align: center;
  font-size: 30px;
  text-transform: uppercase;
  line-height: 100px;
}
 
.form-wrapper .input-wrapper input {
  background-color: rgb(41, 45, 62);
  border: 0;
  width: 100%;
  text-align: center;
  font-size: 15px;
  color: #fff;
  outline: none;
}
 
.form-wrapper .input-wrapper input::placeholder {
  text-transform: uppercase;
}
 
.form-wrapper .input-wrapper .border-wrapper {
  background-image: linear-gradient(to right, #e8198b, #0eb4dd);
  width: 100%;
  height: 50px;
  margin-bottom: 20px;
  border-radius: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}
 
.form-wrapper .input-wrapper .border-wrapper .border-item {
  height: calc(100% - 4px);
  width: calc(100% - 4px);
  border-radius: 30px;
}
 
.form-wrapper .action {
  display: flex;
  justify-content: center;
}
 
.form-wrapper .action .btn {
  width: 60%;
  text-transform: uppercase;
  border: 2px solid #0e92b3;
  text-align: center;
  line-height: 50px;
  border-radius: 30px;
  cursor: pointer;
  
}

.form-wrapper .action .btn2 {
 width: 60%;
 text-transform: uppercase;
 border: 2px solid #0e92b3;
 text-align: center;
 line-height: 50px;
 border-radius: 30px;
 cursor: pointer;
  margin-bottom: 30px; 
}
 
.form-wrapper .action .btn:hover {
  background-image: linear-gradient(120deg, #84fab0 0%, #8fd3f4 100%);
}
 
.form-wrapper .icon-wrapper {
  text-align: center;
  width: 60%;
  margin: 0 auto;
  margin-top: 20px;
  border-top: 1px dashed rgb(146, 146, 146);
  padding: 20px;
}
 
.form-wrapper .icon-wrapper i {
  font-size: 20px;
  color: rgb(187, 187, 187);
  cursor: pointer;
  border: 1px solid #fff;
  padding: 5px;
  border-radius: 20px;
}
 
.form-wrapper .icon-wrapper i:hover {
  background-color: #0e92b3;
}
</style>