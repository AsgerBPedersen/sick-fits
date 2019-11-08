const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');

const { transport, makeANiceEmail } = require('../mail');

const Mutations = {
    async createItem(parent, args, ctx, info) {
        
        console.log(args);
        const item = await ctx.db.mutation.createItem(
          {
            data: {
              ...args,
            },
          },
          info
        );
    
        console.log(item);
    
        return item;
      },
    updateItem(parent, args, ctx, info) {
      const updates = { ...args };
      delete updates.id;
      return ctx.db.mutation.updateItem(
        {
          data: updates,
          where: {
            id: args.id
          }
        }
      )
   
    },
    async deleteItem(parent, args, ctx, info) {
      const where = { id: args.id };
      
      const item = await ctx.db.query.item({ where }, `{ id title }`);

      return ctx.db.mutation.deleteItem({ where }, info);
    },
    async signup(parent, args, ctx, info) {

      args.email = args.email.toLowerCase();

      const password = await bcrypt.hash(args.password, 10);

      const user = await ctx.db.mutation.createUser({
        data: {
          ...args,
          password,
          permissions: {set: ['USER']},
        }
      }, info);
      console.log(user);
      const token = jwt.sign({ userId: user.id}, process.env.APP_SECRET);
      console.log(token);
      ctx.response.cookie('token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365,
      });

      return user;
    },
    async signin(parent, {email, password}, ctx, info) {

      const user = await ctx.db.query.user({where: {email}});
      if(!user) {
        throw new Error(`No such user found for email ${email}`);
      }

      const valid = await bcrypt.compare(password, user.password);
      if(!valid) {
        throw new Error('Invalid password');
      }

      const token = jwt.sign({ userId: user.id}, process.env.APP_SECRET);

      ctx.response.cookie('token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365,
      });
      return user;
    },
    signout(parent, args, ctx, info) {
      ctx.response.clearCookie('token');
      return { message: 'Goodbye!' };
    },
    async requestReset(parent, args, ctx, info) {
      const user =  await ctx.db.query.user({where : {email: args.email}});

      if(!user) {
        throw new Error(`No such user found for email ${args.email}`);
      }
      const randomBytesPromisified = promisify(randomBytes);
      const resetToken = (await randomBytesPromisified(20)).toString('hex');
      const resetTokenExpiry = Date.now() + 3600000;
      const res = await ctx.db.mutation.updateUser({
        where: { email: args.email },
        data: { resetToken, resetTokenExpiry }
      });

      const mailRes = await transport.sendMail({
        from: 'asger@sickfits.com',
        to: user.email,
        subject: 'Your password reset token',
        html: makeANiceEmail(`Your password reset token is here! \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click here to reset!</a>`)
      });

      return { message: "waddup"};
    },
    async resetPassword(parent, { password, confirmPassword, resetToken }, ctx, info) {
      if(password !== confirmPassword) {
        throw new Error(`Passwords doesn't match`);
      }
      const [user] = await ctx.db.query.users({
        where: {
          resetToken: resetToken,
          resetTokenExpiry_gte: Date.now() - 3600000
        }
      });
      console.log(user);
      if(!user) {
        throw new Error(`This user is either invalid or expired`);
      }
      
      const newPassword = await bcrypt.hash(password, 10);

      const updatedUser = await ctx.db.mutation.updateUser({
        where: { email : user.email },
        data: { 
          password: newPassword,
          resetToken: null,
          resetTokenExpiry: null
        }
      });

      const token = jwt.sign({ userId: updatedUser.id}, process.env.APP_SECRET);

      ctx.response.cookie('token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365,
      });

      return updatedUser;
    }
};

module.exports = Mutations;
