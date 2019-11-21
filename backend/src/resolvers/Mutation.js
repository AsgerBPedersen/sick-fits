const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { hasPermission } = require('../utils');

const { transport, makeANiceEmail } = require('../mail');

const Mutations = {
    async createItem(parent, args, ctx, info) {
        if(!ctx.request.userId) {
          throw new Error('You must be logged in to create an item.');
        }
        
        const item = await ctx.db.mutation.createItem(
          {
            data: {
              user : {
                connect : {
                  id: ctx.request.userId
                }
              },
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
      
      const item = await ctx.db.query.item({ where }, `{ id title user { id } }`);

      const ownsItem = item.user.id === ctx.request.userId;
      const hasPerissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));

      if(!ownsItem || !hasPerissions) {
        throw new Error('You dont have permissions to delete this item.');
      }

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
      console.log(user);
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
    },
    async updatePermissions(parent, args, ctx, info) {
      if(!ctx.request.userId) {
        throw new Error('You must be logged in!')
      }
      
      const currentUser = await ctx.db.query.user( { where : { id : ctx.request.userId } }, info );
      console.log(currentUser);

      hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
      return ctx.db.mutation.updateUser({
        data: {
          permissions: {
            set: args.permissions
          }
        },
        where: {
          id: args.userId
        },
      }, info)
    },
    async addToCart(parent, args, ctx, info) {
      const {userId} = ctx.request;
      if(!ctx.request.userId) {
        throw new Error('You must be logged in!')
      }

      const [existingCartItem] = await ctx.db.query.cartItems({
        where: {
          user: { id: userId},
          item: {id: args.id}
        }
      });

      if(existingCartItem) {
        return ctx.db.mutation.updateCartItem({
          where: {id: existingCartItem.id},
          data: {quantity: existingCartItem.quantity + 1}
        });
      }

      return ctx.db.mutation.createCartItem({
        data: {
          user: {
            connect: {
              id: userId
              }
            },
            item: {
              connect: {
                id: args.id
              }
            }
        }
      }, info);
    },
    async removeFromCart(parent, args, ctx, info) {
      const item = await ctx.db.query.cartItem({where : {id : args.id}}, `{ id, user {id}}`);

      if(!item) { 
        throw new Error('No item found.');
      }

      if(item.user.id !== ctx.request.userId) {
        throw new Error('You do not own that item.');
      }

      return ctx.db.mutation.deleteCartItem({where: {id: args.id}}, info);
    }
};

module.exports = Mutations;
