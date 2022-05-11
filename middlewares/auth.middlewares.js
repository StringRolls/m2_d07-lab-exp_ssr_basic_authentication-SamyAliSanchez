const isLoggedin = (req, res, next)=>{
    if(req.session.currentUser) next()
    else next(new Error("You must login"))
  };
  
  module.exports = {
    isLoggedin,
  }
  