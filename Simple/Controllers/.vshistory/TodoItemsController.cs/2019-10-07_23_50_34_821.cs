using System;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;

using Simple.Data;
using Simple.Models;

namespace Simple.Controllers
{
    [Route("api/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [ApiController]
    [Controller]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context) =>
            Context = context ?? throw new ArgumentNullException(nameof(context));

        public ApplicationDbContext Context { get; }

        //Examine the GET methods
        //These methods implement two GET endpoints:
        //GET /api/TodoItems
        //GET /api/TodoItems/{id}
        //Test the app by calling the two endpoints from a browser or Postman.For example:
        //https://localhost:5001/api/TodoItems
        //https://localhost:5001/api/TodoItems/1
        //[
        //  {
        //    "id": 1,
        //    "name": "Item1",
        //    "isComplete": false
        //  }
        //]

        //[HttpGet("/GetTodoItem/{id}")]
        public ActionResult<TodoItem> GetTodoItem(long id) => new TodoItem { Id = id };

        // POST: api/TodoItems
        //[HttpPost("/AddTodoItem")]
        [HttpPost]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken cancellationToken)
        {
            await Context.TodoItems.AddAsync(todoItem, cancellationToken);
            await Context.SaveChangesAsync(cancellationToken);

            //The CreatedAtAction method:
            //Returns an HTTP 201 status code if successful.
            return CreatedAtAction(/*"GetTodoItem"*/nameof(GetTodoItem), new { id = todoItem.Id }, todoItem);
        }



    }
}
