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
      }
};

module.exports = Mutations;
